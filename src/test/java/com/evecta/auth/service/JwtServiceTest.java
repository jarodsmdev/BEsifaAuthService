package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.util.TestDataBuilder;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;

    private static final String SECRET = "jNXUaK6Jm9LkP5QrStVwXyZ0AbCdEfGhIjKlMnOpQrS";
    private static final long EXPIRATION_SECONDS = 3600L;

    private UserEntity user;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "jwtSecret", SECRET);
        ReflectionTestUtils.setField(jwtService, "expirationSeconds", EXPIRATION_SECONDS);

        user = TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "test@example.com", "11111111", "1");
    }

    @Test
    void generateToken_retornaJwtValido() {
        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, List.of("USER_ADMIN"), List.of());

        assertNotNull(tokenData);
        assertNotNull(tokenData.token());
        assertFalse(tokenData.token().isEmpty());
    }

    @Test
    void extractUsername_retornaEmail() {
        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, List.of("USER_ADMIN"), List.of());

        String username = jwtService.extractUsername(tokenData.token());

        assertEquals(user.getEmail(), username);
    }

    @Test
    void extractRoles_retornaListaRoles() {
        List<String> roles = List.of("USER_ADMIN", "USER_SUPERVISOR");
        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, roles, List.of());

        List<String> extracted = jwtService.extractRoles(tokenData.token());

        assertEquals(roles, extracted);
    }

    @Test
    void isTokenValid_tokenValido_retornaTrue() {
        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, List.of("USER_ADMIN"), List.of());

        boolean valid = jwtService.isTokenValid(tokenData.token());

        assertTrue(valid);
    }

    @Test
    void isTokenValid_tokenExpirado_retornaFalse() {
        ReflectionTestUtils.setField(jwtService, "expirationSeconds", -10L);
        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, List.of("USER_ADMIN"), List.of());

        boolean valid = jwtService.isTokenValid(tokenData.token());

        assertFalse(valid);
    }

    @Test
    void isTokenValid_firmaInvalida_retornaFalse() {
        JwtService.AuthTokenData tokenData = jwtService.generateToken(user, List.of("USER_ADMIN"), List.of());
        String tamperedToken = tokenData.token().substring(0, tokenData.token().lastIndexOf('.')) + ".tampered";

        boolean valid = jwtService.isTokenValid(tamperedToken);

        assertFalse(valid);
    }
}
