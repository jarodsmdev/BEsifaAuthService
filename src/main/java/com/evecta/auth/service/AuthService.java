package com.evecta.auth.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;
import java.util.Base64;

import com.evecta.auth.model.AuditAction;
import com.evecta.auth.dto.auth.SessionStatusDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.ChangePasswordRequestDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.dto.auth.PasswordResetRequestDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.repository.IUserRepository;
import com.evecta.auth.util.TokenHashUtil;
import java.util.Random;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Servicio de autenticación.
 *
 * <p>Responsabilidades: - Login/logout de usuarios - Generación y rotación de tokens (access +
 * refresh) - Validación de sesiones - Gestión de recuperación de contraseñas
 *
 * <p>Los tokens se almacenan como cookies HttpOnly para mayor seguridad. El frontend nunca tiene
 * acceso directo a los tokens.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

  private final IUserRepository userRepository;
  private final ITokenRepository tokenRepository;
  private final BCryptPasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final EmailService emailService;
  private final AuditoriaService auditoriaService;

  @Value("${app.jwt.expiration-seconds}")
  private long expirationSeconds;

  @Value("${app.jwt.refresh-expiration-seconds}")
  private long refreshExpirationSeconds;

  /**
   * Resultado del login que contiene tanto la respuesta del usuario como los tokens.
   *
   * @param userResponse DTO con información del usuario (para el frontend)
   * @param accessToken Token JWT de acceso (para cookie HttpOnly o body móvil)
   * @param refreshToken Refresh token opaco (para cookie HttpOnly o body móvil)
   * @param sub Asunto del token (email del usuario)
   * @param iat Timestamp de emisión del token (epoch seconds)
   * @param exp Timestamp de expiración del token (epoch seconds)
   */
  public record LoginResult(
      AuthResponseDTO userResponse,
      String accessToken,
      String refreshToken,
      String sub,
      Long iat,
      Long exp) {}

  /**
   * Autentica un usuario y genera tokens de sesión.
   *
   * <p>Flujo: 1. Valida credenciales 2. Verifica que la cuenta esté activa 3. Bloquea acceso web
   * para usuarios móviles (USER_APP) 4. Genera tokens y los guarda en BD 5. Registra auditoría
   *
   * @param loginRequest Credenciales del usuario
   * @param clientOrigin Origen del cliente ("web" o "app")
   * @return LoginResult con tokens y datos del usuario
   * @throws BadCredentialsException si las credenciales son incorrectas
   */
  @Transactional
  public LoginResult login(LoginRequestDTO loginRequest, String clientOrigin) {

    UserEntity user =
        userRepository
            .findByEmail(loginRequest.getEmail())
            .orElseThrow(() -> new BadCredentialsException("Correo o contraseña incorrectos"));

    if (!user.isActive()) {
      log.warn("Intento de login para cuenta revocada: {}", user.getEmail());
      throw new BadCredentialsException("Esta cuenta ha sido revocada. Contacte al administrador.");
    }

    if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
      throw new BadCredentialsException("Correo o contraseña incorrectos");
    }

    if ("web".equalsIgnoreCase(clientOrigin) && user.getRole() == UserRole.USER_APP) {
      log.warn("Bloqueado login desde web con rol USER_APP: {}", user.getEmail());
      throw new BadCredentialsException(
          "No tienes permisos para acceder a esta plataforma administrativa.");
    }

    // Generar tokens y guardar en BD
    revokeAllUserTokens(user);
    TokenData tokens = generateTokens(user);
    saveAccessToken(user, tokens.accessToken());

    // Iniciar una nueva familia de rotación para esta sesión
    String familyId = Token.generateFamilyId();
    saveRefreshToken(user, tokens.refreshToken(), familyId);

    // Construir respuesta del usuario
    AuthResponseDTO userResponse = buildUserResponse(user);

    log.info("Login exitoso para usuario: {}", user.getEmail());

    // Auditar inicio de sesión
    auditoriaService.registrarAccion(
        user.getEmail(),
        AuditAction.LOGIN.name(),
        java.util.Map.of("Estado", "Exitoso", "rol", user.getRole().name()));

    return new LoginResult(
        userResponse,
        tokens.accessToken(),
        tokens.refreshToken(),
        tokens.sub(),
        tokens.iat(),
        tokens.exp());
  }

  /**
   * Revoca todos los tokens activos del usuario.
   *
   * <p>Este método marca como expirados Y revocados todos los tokens no expirados y no revocados
   * del usuario. Se usa para implementar la política de "una sola sesión activa por usuario".
   *
   * @param user Usuario cuyos tokens serán revocados
   */
  public void revokeAllUserTokens(UserEntity user) {
    List<Token> validTokens =
        tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse(user.getRut());

    if (!validTokens.isEmpty()) {
      validTokens.forEach(
          token -> {
            token.setExpired(true);
            token.setRevoked(true);
          });

      tokenRepository.saveAll(validTokens);
    }
  }

  /**
   * Cierra la sesión de un usuario revocando el token proporcionado.
   *
   * @param token Token a revocar (puede venir de cookie o header Authorization)
   * @throws IllegalArgumentException si el token es inválido
   * @throws IllegalStateException si el token ya está invalidado
   */
  @Transactional
  public void logout(String token) {

    Token storedToken =
        tokenRepository
            .findByToken(token)
            .orElseThrow(() -> new IllegalArgumentException("Token no válido"));

    if (storedToken.isExpired() || storedToken.isRevoked()) {
      throw new IllegalStateException("Token ya está invalidado");
    }

    storedToken.setExpired(true);
    storedToken.setRevoked(true);

    tokenRepository.save(storedToken);

    log.info("Token revocado correctamente");

    // Auditar cierre de sesión
    auditoriaService.registrarAccion(
        storedToken.getUser().getEmail(),
        AuditAction.LOGOUT.name(),
        java.util.Map.of("Motivo", "Cierre de sesión manual o expiración de cliente"));
  }

  /**
   * Valida una sesión desde un token y retorna el estado de la sesión.
   *
   * <p>Este método es utilizado por el endpoint /status para verificar si la sesión del usuario es
   * válida.
   *
   * @param token Token JWT a validar
   * @return SessionStatusDTO con el estado de la sesión
   */
  public SessionStatusDTO validateSession(String token) {

    if (token == null || token.isBlank()) {
      return SessionStatusDTO.builder().valid(false).error("No hay token de sesión").build();
    }

    // Validar firma y expiración del JWT
    if (!jwtService.isTokenValid(token)) {
      return SessionStatusDTO.builder().valid(false).error("Token inválido o expirado").build();
    }

    // Verificar en base de datos
    var storedToken = tokenRepository.findByToken(token).orElse(null);

    if (storedToken == null) {
      return SessionStatusDTO.builder().valid(false).error("Token no encontrado").build();
    }

    if (storedToken.isExpired()) {
      return SessionStatusDTO.builder().valid(false).error("Sesión expirada").build();
    }

    if (storedToken.isRevoked()) {
      return SessionStatusDTO.builder().valid(false).error("Sesión revocada").build();
    }

    // Sesión válida - construir información del usuario
    UserEntity user = storedToken.getUser();
    List<String> roles = resolveRoles(user);

    SessionStatusDTO.UserInfo userInfo =
        SessionStatusDTO.UserInfo.builder()
            .email(user.getEmail())
            .name(user.getName())
            .lastname(user.getLastName())
            .rut(user.getFullRut())
            .roles(roles)
            .build();

    return SessionStatusDTO.builder().valid(true).user(userInfo).build();
  }

  private List<String> resolveRoles(UserEntity user) {
    List<String> roles = new ArrayList<>();

    if (user.getRole() == UserRole.USER_APP) {
      roles.add("USER_APP");
    }

    if (user.getRole() == UserRole.USER_JPL) {
      roles.add("USER_JPL");
    }

    if (user.getRole() == UserRole.USER_SUPERVISOR) {
      roles.add("USER_SUPERVISOR");
    }

    if (user.getRole() == UserRole.USER_ADMIN) {
      roles.add("USER_ADMIN");
    }

    return roles;
  }

  /**
   * Genera los tokens (access + refresh) para un usuario.
   *
   * @param user Usuario para el que se generan los tokens
   * @return TokenData con el access token JWT y refresh token opaco
   */
  private TokenData generateTokens(UserEntity user) {

    List<String> roles = resolveRoles(user);

    JwtService.AuthTokenData tokenData = jwtService.generateToken(user, roles, List.of());

    String refreshToken = generateRefreshToken();

    return new TokenData(
        tokenData.token(), refreshToken, tokenData.sub(), tokenData.iat(), tokenData.exp());
  }

  /**
   * Construye la respuesta del DTO con la información del usuario. Los tokens NO se incluyen en el
   * DTO (se establecen como cookies HttpOnly).
   *
   * @param user Usuario autenticado
   * @return AuthResponseDTO con información del usuario
   */
  private AuthResponseDTO buildUserResponse(UserEntity user) {

    List<String> roles = resolveRoles(user);

    return AuthResponseDTO.builder()
        .email(user.getEmail())
        .name(user.getName())
        .lastname(user.getLastName())
        .rut(user.getFullRut())
        .roles(roles)
        .authType("cookie")
        .build();
  }

  /**
   * Record interno para encapsular los tokens generados.
   *
   * @param accessToken Token JWT de acceso
   * @param refreshToken Refresh token opaco
   * @param sub Asunto del token (email del usuario)
   * @param iat Timestamp de emisión del token (epoch seconds)
   * @param exp Timestamp de expiración del token (epoch seconds)
   */
  private record TokenData(
      String accessToken, String refreshToken, String sub, Long iat, Long exp) {}

  private String generateRefreshToken() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] tokenBytes = new byte[64];
    secureRandom.nextBytes(tokenBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
  }

  private void saveAccessToken(UserEntity user, String jwtToken) {

    Token token =
        Token.builder()
            .user(user)
            .token(jwtToken)
            .tokenType(Token.TokenType.BEARER)
            .expired(false)
            .revoked(false)
            .expiresAt(LocalDateTime.now().plusSeconds(expirationSeconds))
            .build();

    tokenRepository.save(token);
  }

  /**
   * Guarda un refresh token en la BD únicamente como hash SHA-256.
   *
   * <p>El token en texto plano NUNCA se persiste. Solo se almacena:
   * <ul>
   *   <li>{@code tokenHash}: SHA-256(token) en hexadecimal, determinístico para
   *       permitir búsqueda directa {@link ITokenRepository#findByTokenHash(String)}</li>
   *   <li>{@code familyId}: UUID que agrupa la cadena de rotación</li>
   * </ul>
   *
   * <p>Si la BD es comprometida, el atacante solo obtiene hashes (unidireccionales)
   * inutilizables: no puede derivar el valor original ni emitir tokens con ellos.
   *
   * @param user Usuario propietario del token
   * @param refreshToken Refresh token opaco en texto plano (solo se hashea)
   * @param familyId Identificador de la familia de rotación (persistente entre rotaciones)
   */
  private void saveRefreshToken(UserEntity user, String refreshToken, String familyId) {

    // Calcular hash unidireccional y determinístico
    String tokenHash = TokenHashUtil.hashToken(refreshToken);

    Token token =
        Token.builder()
            .user(user)
            .tokenHash(tokenHash)
            .familyId(familyId)
            .tokenType(Token.TokenType.REFRESH)
            .expired(false)
            .revoked(false)
            .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationSeconds))
            .build();

    tokenRepository.save(token);
  }

  /**
   * Guarda un refresh token rotado, registrando el hash del token que reemplazó.
   *
   * <p>El campo {@code replacedByTokenHash} permite detectar reutilización:
   * si el token original se vuelve a enviar después de una rotación, se detecta
   * que ya fue reemplazado (posible compromiso).
   *
   * @param user Usuario propietario del token
   * @param refreshToken Nuevo refresh token en texto plano (solo se hashea)
   * @param familyId Identificador de la familia de rotación
   * @param replacedTokenHash Hash del refresh token que este token reemplaza
   */
  private void saveRotatedRefreshToken(
      UserEntity user, String refreshToken, String familyId, String replacedTokenHash) {

    // Calcular hash unidireccional y determinístico
    String tokenHash = TokenHashUtil.hashToken(refreshToken);

    Token token =
        Token.builder()
            .user(user)
            .tokenHash(tokenHash)
            .familyId(familyId)
            .replacedByTokenHash(replacedTokenHash)
            .tokenType(Token.TokenType.REFRESH)
            .expired(false)
            .revoked(false)
            .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationSeconds))
            .build();

    tokenRepository.save(token);
  }

  /**
   * Resultado del refresh que contiene tanto la respuesta del usuario como los tokens.
   *
   * @param userResponse DTO con información del usuario (para el frontend)
   * @param accessToken Nuevo token JWT de acceso (para cookie HttpOnly o body móvil)
   * @param refreshToken Nuevo refresh token opaco (para cookie HttpOnly o body móvil)
   * @param sub Asunto del token (email del usuario)
   * @param iat Timestamp de emisión del token (epoch seconds)
   * @param exp Timestamp de expiración del token (epoch seconds)
   */
  public record RefreshResult(
      AuthResponseDTO userResponse,
      String accessToken,
      String refreshToken,
      String sub,
      Long iat,
      Long exp) {}

  /**
   * Renueva los tokens usando un refresh token válido.
   *
   * <p>Este método implementa las siguientes protecciones de seguridad:
   * <ul>
   *   <li><b>Hashing:</b> el refresh token se busca por su hash SHA-256, nunca en texto plano</li>
   *   <li><b>Rotación:</b> cada uso genera un nuevo refresh token; el anterior queda revocado
   *       y marcado con el hash del reemplazo ({@code replacedByTokenHash})</li>
   *   <li><b>Detección de reutilización:</b> si un refresh token ya reemplazado se vuelve a usar,
   *       se trata como un posible compromiso y se revoca TODA la familia de tokens</li>
   * </ul>
   *
   * @param refreshToken Refresh token actual a renovar (texto plano enviado por el cliente)
   * @return RefreshResult con nuevos tokens y datos del usuario
   * @throws IllegalArgumentException si el token es inválido o se detecta reutilización
   * @throws IllegalStateException si el token está expirado o revocado
   */
  @Transactional
  public RefreshResult refresh(String refreshToken) {

    if (refreshToken == null || refreshToken.isBlank()) {
      throw new IllegalArgumentException("Refresh token inválido");
    }

    // 1. Buscar el token en BD por su hash (nunca por texto plano)
    String tokenHash = TokenHashUtil.hashToken(refreshToken);
    Token storedToken = tokenRepository.findByTokenHash(tokenHash).orElse(null);

    if (storedToken == null) {
      // El token no existe en BD (expiró la sesión completa o nunca se emitió)
      throw new IllegalArgumentException("Refresh token inválido");
    }

    // 2. DETECCIÓN DE REUTILIZACIÓN:
    //    Si este token YA fue reemplazado (replacedByTokenHash != null) y alguien
    //    lo vuelve a enviar, significa que fue clonado, robado o reutilizado.
    if (storedToken.getReplacedByTokenHash() != null) {
      String email =
          storedToken.getUser() != null ? storedToken.getUser().getEmail() : "desconocido";
      log.warn("Posible ROBO/REUSO de refresh token detectado para usuario: {}", email);

      // Un token reutilizado implica que el original pudo ser clonado:
      // se revoca toda la familia para invalidar la sesión completa.
      revokeTokenFamilyByToken(storedToken);

      // Auditar el incidente de seguridad
      auditoriaService.registrarAccion(
          email,
          AuditAction.LOGOUT.name(),
          java.util.Map.of(
              "Motivo",
              "Reutilización de refresh token detectada: se revocó toda la familia de tokens"));

      throw new IllegalArgumentException(
          "Refresh token inválido. Se detectó un posible uso indebido del token.");
    }

    // 3. VALIDACIÓN estándar del token
    if (storedToken.isExpired() || storedToken.isRevoked()) {
      throw new IllegalStateException("Refresh token inválido");
    }

    if (storedToken.getExpiresAt().isBefore(LocalDateTime.now())) {
      storedToken.setExpired(true);
      tokenRepository.save(storedToken);
      throw new IllegalStateException("Refresh token expirado");
    }

    if (storedToken.getTokenType() != Token.TokenType.REFRESH) {
      throw new IllegalStateException("Token inválido");
    }

    UserEntity user = storedToken.getUser();

    // 4. ROTACIÓN: marcar el token actual como expirado y revocado
    //    (un refresh token se usa UNA sola vez)
    storedToken.setExpired(true);
    storedToken.setRevoked(true);
    tokenRepository.save(storedToken);

    // 5. Revocar los demás tokens activos del usuario (política de una sesión activa)
    revokeAllUserTokens(user);

    // 6. GENERAR NUEVO PAR DE TOKENS (rotación completa)
    TokenData tokens = generateTokens(user);

    // Guardar nuevo access token (JWT, se valida por firma)
    saveAccessToken(user, tokens.accessToken());

    // Guardar nuevo refresh token en la MISMA familia, registrando el reemplazo
    String previousHash = storedToken.getTokenHash();
    saveRotatedRefreshToken(user, tokens.refreshToken(), storedToken.getFamilyId(), previousHash);

    // Construir respuesta del usuario
    AuthResponseDTO userResponse = buildUserResponse(user);

    return new RefreshResult(
        userResponse,
        tokens.accessToken(),
        tokens.refreshToken(),
        tokens.sub(),
        tokens.iat(),
        tokens.exp());
  }

  /**
   * Revoca TODA la familia de tokens de un usuario a partir de un token detectado.
   *
   * <p>Cuando se detecta la reutilización de un refresh token (posible compromiso),
   * se revocan todos los tokens que comparten el {@code familyId}. Esto incluye
   * tokens de acceso y refresh de la misma sesión, forzando al usuario a
   * autenticarse nuevamente.
   *
   * @param detectedToken Token que se detectó como reutilizado (pertenece a la familia a revocar)
   */
  private void revokeTokenFamilyByToken(Token detectedToken) {

    if (detectedToken.getFamilyId() == null) {
      log.warn(
          "Token sin familyId detectado (id={}); revocando solo el token individual",
          detectedToken.getIdToken());

      detectedToken.setRevoked(true);
      detectedToken.setExpired(true);
      tokenRepository.save(detectedToken);
      return;
    }

    List<Token> familyTokens = tokenRepository.findAllByFamilyId(detectedToken.getFamilyId());

    if (!familyTokens.isEmpty()) {
      familyTokens.forEach(
          token -> {
            token.setRevoked(true);
            token.setExpired(true);
          });
      tokenRepository.saveAll(familyTokens);

      log.warn(
          "Revocada familia de tokens '{}' ({} tokens) por detección de reutilización",
          detectedToken.getFamilyId(),
          familyTokens.size());
    }
  }

  @Transactional
  public void initiatePasswordRecovery(String email) {
    log.info("Iniciando recuperación de contraseña para: {}", email);
    UserEntity user =
        userRepository
            .findByEmail(email)
            .orElseThrow(
                () ->
                    new IllegalArgumentException("El correo ingresado no se encuentra registrado"));

    if (!user.isActive()) {
      throw new IllegalArgumentException(
          "Esta cuenta se encuentra inactiva. Contacte al administrador.");
    }

    // Generar código numérico de 6 dígitos
    Random random = new Random();
    String code = String.format("%06d", random.nextInt(1000000));

    user.setRecoveryCode(code);
    user.setRecoveryCodeExpiry(LocalDateTime.now().plusMinutes(15));
    user.setRecoveryAttempts(0);

    userRepository.save(user);

    // Envío real del correo
    emailService.sendRecoveryCode(user.getEmail(), code);

    // Auditar solicitud de recuperar contraseña
    auditoriaService.registrarAccion(
        user.getEmail(),
        AuditAction.SOLICITUD_RECUPERACION_CLAVE.name(),
        java.util.Map.of("Estado", "Correo de recuperación enviado"));
  }

  @Transactional
  public void changePassword(String email, ChangePasswordRequestDTO request) {
    log.info("Cambio de contraseña solicitado para: {}", email);

    UserEntity user =
        userRepository
            .findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

    if (!user.isActive()) {
      throw new IllegalArgumentException(
          "Esta cuenta se encuentra inactiva. Contacte al administrador.");
    }

    if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
      throw new IllegalArgumentException("La contraseña actual no es correcta");
    }

    if (request.getOldPassword().equals(request.getNewPassword())) {
      throw new IllegalArgumentException("La nueva contraseña debe ser diferente a la actual");
    }

    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    userRepository.save(user);

    revokeAllUserTokens(user);

    log.info("Cambio de contraseña exitoso para: {}", email);
    auditoriaService.registrarAccion(
        user.getEmail(),
        AuditAction.CAMBIO_CLAVE.name(),
        java.util.Map.of(
            "Estado",
            "Exitoso",
            "Motivo",
            "Cambio voluntario desde app móvil",
            "sesiones_antiguas_revocadas",
            true));
  }

  @Transactional(noRollbackFor = IllegalArgumentException.class)
  public void resetPassword(PasswordResetRequestDTO request) {
    log.info("Procesando restablecimiento de contraseña para: {}", request.getEmail());
    UserEntity user =
        userRepository
            .findByEmail(request.getEmail())
            .orElseThrow(
                () ->
                    new IllegalArgumentException("El correo ingresado no se encuentra registrado"));

    if (!user.isActive()) {
      throw new IllegalArgumentException(
          "Esta cuenta se encuentra inactiva. Contacte al administrador.");
    }

    if (user.getRecoveryCode() == null || user.getRecoveryCodeExpiry() == null) {
      throw new IllegalArgumentException(
          "No se ha solicitado una recuperación de contraseña o el código ya fue utilizado.");
    }

    // Validar expiración por tiempo
    if (LocalDateTime.now().isAfter(user.getRecoveryCodeExpiry())) {
      // Limpiar código expirado
      user.setRecoveryCode(null);
      user.setRecoveryCodeExpiry(null);
      user.setRecoveryAttempts(0);
      userRepository.save(user);
      throw new IllegalArgumentException(
          "El código de recuperación ha expirado. Por favor, solicite uno nuevo.");
    }

    // Validar intentos fallidos
    int currentAttempts = user.getRecoveryAttempts() == null ? 0 : user.getRecoveryAttempts();
    if (currentAttempts >= 3) {
      // Limpiar código bloqueado
      user.setRecoveryCode(null);
      user.setRecoveryCodeExpiry(null);
      user.setRecoveryAttempts(0);
      userRepository.save(user);
      throw new IllegalArgumentException(
          "Código bloqueado por superar el límite de intentos (máximo 3). Por favor, solicite uno nuevo.");
    }

    // Validar coincidencia de código
    if (!user.getRecoveryCode().equals(request.getCode())) {
      int newAttempts = currentAttempts + 1;
      user.setRecoveryAttempts(newAttempts);
      int remaining = 3 - newAttempts;
      userRepository.save(user);

      if (remaining <= 0) {
        // Limpiar código inmediatamente al llegar al límite
        user.setRecoveryCode(null);
        user.setRecoveryCodeExpiry(null);
        user.setRecoveryAttempts(0);
        userRepository.save(user);
        throw new IllegalArgumentException(
            "Código incorrecto. Límite de intentos superado. Código bloqueado.");
      }
      throw new IllegalArgumentException(
          "El código ingresado es incorrecto. Intentos restantes: " + remaining);
    }

    // Restablecer contraseña con éxito
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));

    // Limpiar campos de recuperación
    user.setRecoveryCode(null);
    user.setRecoveryCodeExpiry(null);
    user.setRecoveryAttempts(0);

    userRepository.save(user);

    // Revocar todos los tokens JWT antiguos para cerrar todas las sesiones activas
    revokeAllUserTokens(user);

    log.info("Restablecimiento de contraseña exitoso para usuario: {}", user.getEmail());

    // Auditar cambio de contraseña
    auditoriaService.registrarAccion(
        user.getEmail(),
        AuditAction.CAMBIO_CLAVE.name(),
        java.util.Map.of(
            "Estado", "Exitoso",
            "Motivo", "Recuperación de contraseña mediante código SMTP",
            "sesiones_antiguas_revocadas", true));
  }
}
