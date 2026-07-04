package com.evecta.auth.util;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public final class TestDataBuilder {

    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private TestDataBuilder() {
    }

    public static UserEntity createUserEntity(UserRole role, String email, String rut, String dv) {
        return UserEntity.builder()
                .userId(UUID.randomUUID())
                .rut(rut)
                .dv(dv)
                .name("Test")
                .lastName("User")
                .email(email)
                .password(passwordEncoder.encode("TestPass123"))
                .role(role)
                .isActive(true)
                .recoveryAttempts(0)
                .createdAt(LocalDateTime.now())
                .modifiedAt(LocalDateTime.now())
                .build();
    }

    public static LoginRequestDTO createLoginRequest(String email, String password) {
        return LoginRequestDTO.builder()
                .email(email)
                .password(password)
                .build();
    }

    public static Token createToken(UserEntity user, Token.TokenType type, boolean revoked, boolean expired) {
        return Token.builder()
                .token(UUID.randomUUID().toString())
                .tokenType(type)
                .revoked(revoked)
                .expired(expired)
                .user(user)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .createdAt(LocalDateTime.now())
                .modifiedAt(LocalDateTime.now())
                .build();
    }

    public static UserCreateDTO createUserCreateDTO() {
        return UserCreateDTO.builder()
                .rut("11111111")
                .dv("1")
                .name("Test")
                .lastName("User")
                .email("test@example.com")
                .role(UserRole.USER_ADMIN)
                .password("TestPass123")
                .build();
    }

    public static AuthResponseDTO createAuthResponseDTO() {
        return AuthResponseDTO.builder()
                .accessToken("test-access-token")
                .refreshToken("test-refresh-token")
                .tokenType("Bearer")
                .sub("test@example.com")
                .iat(1678886400L)
                .exp(1678890000L)
                .roles(List.of("USER_ADMIN"))
                .permisos(List.of())
                .build();
    }
}
