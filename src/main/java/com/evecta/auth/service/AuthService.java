package com.evecta.auth.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.evecta.auth.dto.auth.AuthResponseDTO;
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

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final IUserRepository userRepository;
    private final ITokenRepository tokenRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final EmailService emailService;

    @Value("${app.jwt.expiration-seconds:3600}")
    private long expirationSeconds;

    @Value("${app.jwt.refresh-expiration-seconds:86400}")
    private long refreshExpirationSeconds;

    @Transactional
    public AuthResponseDTO login(LoginRequestDTO loginRequest) {

        UserEntity user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Correo o contraseña incorrectos"));

        if (!user.isActive()) {
            log.warn("Intento de login para cuenta revocada: {}", user.getEmail());
            throw new BadCredentialsException("Esta cuenta ha sido revocada. Contacte al administrador.");
        }

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Correo o contraseña incorrectos");
        }

        AuthResponseDTO response = issueTokenForUser(user);

        log.info("Login exitoso para usuario: {}", user.getEmail());

        return response;
    }

    @Transactional
    public AuthResponseDTO issueTokenForUser(UserEntity user) {

        revokeAllUserTokens(user);

        AuthResponseDTO response = buildAuthResponse(user);

        saveAccessToken(user, response.getAccessToken());

        saveRefreshToken(user, response.getRefreshToken());

        return response;
    }

    public void revokeAllUserTokens(UserEntity user) {
        List<Token> validTokens = tokenRepository
                .findAllByUser_RutAndExpiredFalseAndRevokedFalse(user.getRut());

        if (!validTokens.isEmpty()) {
            validTokens.forEach(token -> {
                token.setExpired(true);
                token.setRevoked(true);
            });

            tokenRepository.saveAll(validTokens);
        }
    }

    @Transactional
    public void logout(String authHeader) {

        String token = authHeader.substring(7);

        Token storedToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Token no válido"));

        if (storedToken.isExpired() || storedToken.isRevoked()) {
            throw new IllegalStateException("Token ya está invalidado");
        }

        storedToken.setExpired(true);
        storedToken.setRevoked(true);

        tokenRepository.save(storedToken);

        log.info("Token revocado correctamente");
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

    private AuthResponseDTO buildAuthResponse(UserEntity user) {

        List<String> roles = resolveRoles(user);

        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, roles, List.of());

        String refreshToken = generateRefreshToken();

        return AuthResponseDTO.builder()
                .accessToken(tokenData.token())
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .sub(tokenData.sub())
                .iat(tokenData.iat())
                .exp(tokenData.exp())
                .roles(tokenData.roles())
                .build();
    }

    private String generateRefreshToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[64];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(tokenBytes);
    }

    private void saveAccessToken(UserEntity user, String jwtToken) {

        Token token = Token.builder()
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

        Token token = Token.builder()
                .user(user)
                .token(refreshToken)
                .tokenType(Token.TokenType.REFRESH)
                .expired(false)
                .revoked(false)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationSeconds))
                .build();

        tokenRepository.save(token);
    }

    @Transactional
    public AuthResponseDTO refresh(String refreshToken) {

        Token storedToken = tokenRepository.findByToken(refreshToken)
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
        AuthResponseDTO response = buildAuthResponse(user);

        // GUARDAR NUEVOS TOKENS
        saveAccessToken(user, response.getAccessToken());

        saveRefreshToken(user, response.getRefreshToken());

        return response;
    }

    @Transactional
    public void initiatePasswordRecovery(String email) {
        log.info("Iniciando recuperación de contraseña para: {}", email);
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("El correo ingresado no se encuentra registrado"));

        if (!user.isActive()) {
            throw new IllegalArgumentException("Esta cuenta se encuentra inactiva. Contacte al administrador.");
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
    }

    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public void resetPassword(PasswordResetRequestDTO request) {
        log.info("Procesando restablecimiento de contraseña para: {}", request.getEmail());
        UserEntity user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("El correo ingresado no se encuentra registrado"));

        if (!user.isActive()) {
            throw new IllegalArgumentException("Esta cuenta se encuentra inactiva. Contacte al administrador.");
        }

        if (user.getRecoveryCode() == null || user.getRecoveryCodeExpiry() == null) {
            throw new IllegalArgumentException("No se ha solicitado una recuperación de contraseña o el código ya fue utilizado.");
        }

        // Validar expiración por tiempo
        if (LocalDateTime.now().isAfter(user.getRecoveryCodeExpiry())) {
            // Limpiar código expirado
            user.setRecoveryCode(null);
            user.setRecoveryCodeExpiry(null);
            user.setRecoveryAttempts(0);
            userRepository.save(user);
            throw new IllegalArgumentException("El código de recuperación ha expirado. Por favor, solicite uno nuevo.");
        }

        // Validar intentos fallidos
        int currentAttempts = user.getRecoveryAttempts() == null ? 0 : user.getRecoveryAttempts();
        if (currentAttempts >= 3) {
            // Limpiar código bloqueado
            user.setRecoveryCode(null);
            user.setRecoveryCodeExpiry(null);
            user.setRecoveryAttempts(0);
            userRepository.save(user);
            throw new IllegalArgumentException("Código bloqueado por superar el límite de intentos (máximo 3). Por favor, solicite uno nuevo.");
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
                throw new IllegalArgumentException("Código incorrecto. Límite de intentos superado. Código bloqueado.");
            }
            throw new IllegalArgumentException("El código ingresado es incorrecto. Intentos restantes: " + remaining);
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
    }
}