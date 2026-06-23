package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.ChangePasswordRequestDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.dto.auth.PasswordResetRequestDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.repository.IUserRepository;
import com.evecta.auth.util.TestDataBuilder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private IUserRepository userRepository;

    @Mock
    private ITokenRepository tokenRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private AuditoriaService auditoriaService;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private AuthService authService;

    @Captor
    private ArgumentCaptor<Token> tokenCaptor;

    @Captor
    private ArgumentCaptor<Map<String, Object>> detallesCaptor;

    private UserEntity activeUser;
    private UserEntity inactiveUser;
    private UserEntity userAppUser;
    private LoginRequestDTO loginRequest;
    private ChangePasswordRequestDTO changePasswordRequest;
    private PasswordResetRequestDTO passwordResetRequest;
    private JwtService.AuthTokenData authTokenData;
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "TestPass123";

    @BeforeEach
    void setUp() {
        activeUser = TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, TEST_EMAIL, "11111111", "1");
        inactiveUser = TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "inactive@example.com", "22222222", "2");
        inactiveUser.setActive(false);

        userAppUser = TestDataBuilder.createUserEntity(UserRole.USER_APP, "userapp@example.com", "33333333", "3");

        loginRequest = TestDataBuilder.createLoginRequest(TEST_EMAIL, TEST_PASSWORD);

        changePasswordRequest = ChangePasswordRequestDTO.builder()
                .oldPassword("OldPass123")
                .newPassword("NewPass456")
                .build();

        passwordResetRequest = PasswordResetRequestDTO.builder()
                .email(TEST_EMAIL)
                .code("123456")
                .newPassword("NewPass789")
                .build();

        authTokenData = new JwtService.AuthTokenData(
                "test-access-token",
                TEST_EMAIL,
                1000L,
                2000L,
                List.of("USER_ADMIN"),
                List.of());
    }

    @Test
    void login_conCredencialesValidas_retornaAuthResponse() {
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches(TEST_PASSWORD, activeUser.getPassword())).thenReturn(true);
        when(tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse(activeUser.getRut()))
                .thenReturn(List.of());
        when(jwtService.generateToken(eq(activeUser), eq(List.of("USER_ADMIN")), eq(List.of())))
                .thenReturn(authTokenData);
        when(tokenRepository.save(any(Token.class))).thenAnswer(inv -> inv.getArgument(0));

        AuthResponseDTO response = authService.login(loginRequest, "web");

        assertNotNull(response);
        assertEquals(authTokenData.token(), response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(activeUser.getEmail(), response.getSub());
        assertEquals(List.of("USER_ADMIN"), response.getRoles());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(TEST_EMAIL),
                eq("LOGIN"),
                any(Map.class));
    }

    @Test
    void login_conPasswordIncorrecto_lanzaBadCredentials() {
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches(TEST_PASSWORD, activeUser.getPassword())).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> authService.login(loginRequest, "web"));
    }

    @Test
    void login_usuarioInactivo_lanzaBadCredentials() {
        inactiveUser.setActive(false);
        when(userRepository.findByEmail("inactive@example.com")).thenReturn(Optional.of(inactiveUser));
        LoginRequestDTO req = TestDataBuilder.createLoginRequest("inactive@example.com", TEST_PASSWORD);

        assertThrows(BadCredentialsException.class, () -> authService.login(req, "web"));
    }

    @Test
    void login_userAppDesdeWeb_lanzaExcepcion() {
        when(userRepository.findByEmail("userapp@example.com")).thenReturn(Optional.of(userAppUser));
        when(passwordEncoder.matches(TEST_PASSWORD, userAppUser.getPassword())).thenReturn(true);
        LoginRequestDTO req = TestDataBuilder.createLoginRequest("userapp@example.com", TEST_PASSWORD);

        assertThrows(BadCredentialsException.class, () -> authService.login(req, "web"));
    }

    @Test
    void login_userAppDesdeMobile_retornaTokens() {
        when(userRepository.findByEmail("userapp@example.com")).thenReturn(Optional.of(userAppUser));
        when(passwordEncoder.matches(TEST_PASSWORD, userAppUser.getPassword())).thenReturn(true);
        when(tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse(userAppUser.getRut()))
                .thenReturn(List.of());
        JwtService.AuthTokenData appTokenData = new JwtService.AuthTokenData(
                "app-access-token", "userapp@example.com", 1000L, 2000L,
                List.of("USER_APP"), List.of());
        when(jwtService.generateToken(eq(userAppUser), eq(List.of("USER_APP")), eq(List.of())))
                .thenReturn(appTokenData);
        when(tokenRepository.save(any(Token.class))).thenAnswer(inv -> inv.getArgument(0));
        LoginRequestDTO req = TestDataBuilder.createLoginRequest("userapp@example.com", TEST_PASSWORD);

        AuthResponseDTO response = authService.login(req, "mobile");

        assertNotNull(response);
        assertEquals(appTokenData.token(), response.getAccessToken());
        assertEquals(List.of("USER_APP"), response.getRoles());
    }

    @Test
    void logout_conTokenValido_revocaYAudita() {
        String jwtToken = "Bearer valid-jwt-token";
        Token storedToken = TestDataBuilder.createToken(activeUser, Token.TokenType.BEARER, false, false);

        when(tokenRepository.findByToken("valid-jwt-token")).thenReturn(Optional.of(storedToken));

        authService.logout(jwtToken);

        assertTrue(storedToken.isExpired());
        assertTrue(storedToken.isRevoked());
        verify(tokenRepository).save(storedToken);
        verify(auditoriaService).registrarAccionAsincrona(
                eq(TEST_EMAIL),
                eq("LOGOUT"),
                any(Map.class));
    }

    @Test
    void refresh_conTokenValido_emiteNuevosTokens() {
        Token refreshTokenEntity = TestDataBuilder.createToken(activeUser, Token.TokenType.REFRESH, false, false);
        refreshTokenEntity.setExpiresAt(LocalDateTime.now().plusHours(1));

        when(tokenRepository.findByToken("valid-refresh-token")).thenReturn(Optional.of(refreshTokenEntity));
        when(tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse(activeUser.getRut()))
                .thenReturn(List.of());
        when(jwtService.generateToken(eq(activeUser), eq(List.of("USER_ADMIN")), eq(List.of())))
                .thenReturn(authTokenData);
        when(tokenRepository.save(any(Token.class))).thenAnswer(inv -> inv.getArgument(0));

        AuthResponseDTO response = authService.refresh("valid-refresh-token");

        assertNotNull(response);
        assertEquals(authTokenData.token(), response.getAccessToken());
        assertNotNull(response.getRefreshToken());
    }

    @Test
    void refresh_conTokenRevocado_lanzaExcepcion() {
        Token revokedToken = TestDataBuilder.createToken(activeUser, Token.TokenType.REFRESH, true, false);

        when(tokenRepository.findByToken("revoked-refresh-token")).thenReturn(Optional.of(revokedToken));

        assertThrows(IllegalStateException.class, () -> authService.refresh("revoked-refresh-token"));
    }

    @Test
    void changePassword_conDatosValidos_cambiaPassword() {
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.matches(changePasswordRequest.getOldPassword(), activeUser.getPassword()))
                .thenReturn(true);
        when(passwordEncoder.encode(changePasswordRequest.getNewPassword())).thenReturn("encoded-new-password");
        when(tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse(activeUser.getRut()))
                .thenReturn(List.of());

        authService.changePassword(TEST_EMAIL, changePasswordRequest);

        verify(userRepository).save(activeUser);
        assertEquals("encoded-new-password", activeUser.getPassword());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(TEST_EMAIL),
                eq("CAMBIO_CLAVE"),
                any(Map.class));
    }

    @Test
    void initiatePasswordRecovery_conEmailValido_enviaCodigo() {
        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(activeUser));

        authService.initiatePasswordRecovery(TEST_EMAIL);

        assertNotNull(activeUser.getRecoveryCode());
        assertEquals(6, activeUser.getRecoveryCode().length());
        assertNotNull(activeUser.getRecoveryCodeExpiry());
        assertEquals(0, activeUser.getRecoveryAttempts());
        verify(userRepository).save(activeUser);
        verify(emailService).sendRecoveryCode(eq(TEST_EMAIL), anyString());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(TEST_EMAIL),
                eq("SOLICITUD_RECUPERACION_CLAVE"),
                any(Map.class));
    }

    @Test
    void resetPassword_conCodigoValido_restablecePassword() {
        activeUser.setRecoveryCode("123456");
        activeUser.setRecoveryCodeExpiry(LocalDateTime.now().plusMinutes(10));
        activeUser.setRecoveryAttempts(0);

        when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(activeUser));
        when(passwordEncoder.encode(passwordResetRequest.getNewPassword())).thenReturn("encoded-reset-password");
        when(tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse(activeUser.getRut()))
                .thenReturn(List.of());

        authService.resetPassword(passwordResetRequest);

        assertEquals("encoded-reset-password", activeUser.getPassword());
        assertNull(activeUser.getRecoveryCode());
        assertNull(activeUser.getRecoveryCodeExpiry());
        assertEquals(0, activeUser.getRecoveryAttempts());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(TEST_EMAIL),
                eq("CAMBIO_CLAVE"),
                any(Map.class));
    }
}
