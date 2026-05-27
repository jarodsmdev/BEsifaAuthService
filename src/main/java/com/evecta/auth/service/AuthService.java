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
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.repository.IUserRepository;

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
}