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
import java.util.Random;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Servicio de autenticación.
 * 
 * Responsabilidades:
 * - Login/logout de usuarios
 * - Generación y rotación de tokens (access + refresh)
 * - Validación de sesiones
 * - Gestión de recuperación de contraseñas
 * 
 * Los tokens se almacenan como cookies HttpOnly para mayor seguridad.
 * El frontend nunca tiene acceso directo a los tokens.
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

  @Value("${app.jwt.expiration-seconds:3600}")
  private long expirationSeconds;

  @Value("${app.jwt.refresh-expiration-seconds:86400}")
  private long refreshExpirationSeconds;

  /**
   * Resultado del login que contiene tanto la respuesta del usuario como los tokens.
   * 
   * @param userResponse DTO con información del usuario (para el frontend)
   * @param accessToken Token JWT de acceso (para cookie HttpOnly)
   * @param refreshToken Refresh token opaco (para cookie HttpOnly)
   */
  public record LoginResult(AuthResponseDTO userResponse, String accessToken, String refreshToken) {
  }

  /**
   * Autentica un usuario y genera tokens de sesión.
   * 
   * Flujo:
   * 1. Valida credenciales
   * 2. Verifica que la cuenta esté activa
   * 3. Bloquea acceso web para usuarios móviles (USER_APP)
   * 4. Genera tokens y los guarda en BD
   * 5. Registra auditoría
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
    saveRefreshToken(user, tokens.refreshToken());

    // Construir respuesta del usuario
    AuthResponseDTO userResponse = buildUserResponse(user);

    log.info("Login exitoso para usuario: {}", user.getEmail());

    // Auditar inicio de sesión
    auditoriaService.registrarAccion(
        user.getEmail(),
        AuditAction.LOGIN.name(),
        java.util.Map.of("Estado", "Exitoso", "rol", user.getRole().name()));

    return new LoginResult(userResponse, tokens.accessToken(), tokens.refreshToken());
  }

  /**
   * Revoca todos los tokens activos del usuario.
   * 
   * Este método marca como expirados Y revocados todos los tokens
   * no expirados y no revocados del usuario. Se usa para implementar
   * la política de "una sola sesión activa por usuario".
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
   * Este método es utilizado por el endpoint /status para verificar
   * si la sesión del usuario es válida.
   * 
   * @param token Token JWT a validar
   * @return SessionStatusDTO con el estado de la sesión
   */
  public SessionStatusDTO validateSession(String token) {

    if (token == null || token.isBlank()) {
      return SessionStatusDTO.builder()
          .valid(false)
          .error("No hay token de sesión")
          .build();
    }

    // Validar firma y expiración del JWT
    if (!jwtService.isTokenValid(token)) {
      return SessionStatusDTO.builder()
          .valid(false)
          .error("Token inválido o expirado")
          .build();
    }

    // Verificar en base de datos
    var storedToken = tokenRepository.findByToken(token).orElse(null);

    if (storedToken == null) {
      return SessionStatusDTO.builder()
          .valid(false)
          .error("Token no encontrado")
          .build();
    }

    if (storedToken.isExpired()) {
      return SessionStatusDTO.builder()
          .valid(false)
          .error("Sesión expirada")
          .build();
    }

    if (storedToken.isRevoked()) {
      return SessionStatusDTO.builder()
          .valid(false)
          .error("Sesión revocada")
          .build();
    }

    // Sesión válida - construir información del usuario
    UserEntity user = storedToken.getUser();
    List<String> roles = resolveRoles(user);

    SessionStatusDTO.UserInfo userInfo = SessionStatusDTO.UserInfo.builder()
        .email(user.getEmail())
        .name(user.getName())
        .lastname(user.getLastName())
        .rut(user.getFullRut())
        .roles(roles)
        .build();

    return SessionStatusDTO.builder()
        .valid(true)
        .user(userInfo)
        .build();
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

    return new TokenData(tokenData.token(), refreshToken);
  }

  /**
   * Construye la respuesta del DTO con la información del usuario.
   * Los tokens NO se incluyen en el DTO (se establecen como cookies HttpOnly).
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
   * @param accessToken  Token JWT de acceso
   * @param refreshToken Refresh token opaco
   */
  private record TokenData(String accessToken, String refreshToken) {
  }

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

  private void saveRefreshToken(UserEntity user, String refreshToken) {

    Token token =
        Token.builder()
            .user(user)
            .token(refreshToken)
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
   * @param accessToken Nuevo token JWT de acceso (para cookie HttpOnly)
   * @param refreshToken Nuevo refresh token opaco (para cookie HttpOnly)
   */
  public record RefreshResult(AuthResponseDTO userResponse, String accessToken, String refreshToken) {
  }

  /**
   * Renueva los tokens usando un refresh token válido.
   * 
   * Este método implementa la rotación de refresh tokens:
   * 1. Valida el refresh token actual
   * 2. Revoca TODOS los tokens del usuario (incluyendo el actual)
   * 3. Genera un nuevo par de tokens (access + refresh)
   * 4. Guarda los nuevos tokens en la base de datos
   * 
   * @param refreshToken Refresh token actual a renovar
   * @return RefreshResult con nuevos tokens y datos del usuario
   * @throws IllegalArgumentException si el token es inválido
   * @throws IllegalStateException si el token está expirado o revocado
   */
  @Transactional
  public RefreshResult refresh(String refreshToken) {

    Token storedToken =
        tokenRepository
            .findByToken(refreshToken)
            .orElseThrow(() -> new IllegalArgumentException("Refresh token inválido"));

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

    // REVOCAR TOKENS ANTERIORES
    revokeAllUserTokens(user);

    // GENERAR NUEVOS TOKENS
    TokenData tokens = generateTokens(user);

    // GUARDAR NUEVOS TOKENS
    saveAccessToken(user, tokens.accessToken());

    saveRefreshToken(user, tokens.refreshToken());

    // Construir respuesta del usuario
    AuthResponseDTO userResponse = buildUserResponse(user);

    return new RefreshResult(userResponse, tokens.accessToken(), tokens.refreshToken());
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

    UserEntity user = userRepository.findByEmail(email)
        .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

    if (!user.isActive()) {
      throw new IllegalArgumentException("Esta cuenta se encuentra inactiva. Contacte al administrador.");
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
        java.util.Map.of("Estado", "Exitoso", "Motivo", "Cambio voluntario desde app móvil", "sesiones_antiguas_revocadas", true));
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
