package com.evecta.auth.service;

import java.util.ArrayList;
import java.util.List;

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

    @Transactional
    public AuthResponseDTO login(LoginRequestDTO loginRequest) {

        UserEntity user = userRepository.findActiveByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        AuthResponseDTO response = issueTokenForUser(user);

        log.info("Login exitoso para usuario: {}", user.getEmail());

        return response;
    }

    @Transactional
    public AuthResponseDTO issueTokenForUser(UserEntity user) {
        revokeAllUserTokens(user);

        AuthResponseDTO response = buildAuthResponse(user);

        saveUserToken(user, response.getAccessToken());

        return response;
    }

    private void saveUserToken(UserEntity user, String jwtToken) {
        Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(Token.TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
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

        if (user.getRole() == UserRole.USER_APP){
            roles.add("USER_APP");
        }

        if (user.getRole() == UserRole.USER_JPL){
            roles.add("USER_JPL");
        }

        if (user.getRole() == UserRole.USER_SUPERVISOR){
            roles.add("USER_SUPERVISOR");
        }

        if (user.getRole() == UserRole.USER_ADMIN){
            roles.add("USER_ADMIN");
        }

        return roles;
    }

    private AuthResponseDTO buildAuthResponse(UserEntity user) {

        List<String> roles = resolveRoles(user);

        JwtService.AuthTokenData tokenData =
                jwtService.generateToken(user, roles, List.of());

        return AuthResponseDTO.builder()
                .accessToken(tokenData.token())
                .tokenType("Bearer")
                .sub(tokenData.sub())
                .iat(tokenData.iat())
                .exp(tokenData.exp())
                .roles(tokenData.roles())
                .build();
    }
}