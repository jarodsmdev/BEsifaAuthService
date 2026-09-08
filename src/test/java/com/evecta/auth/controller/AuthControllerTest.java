package com.evecta.auth.controller;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.ChangePasswordRequestDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.dto.auth.PasswordRecoveryRequestDTO;
import com.evecta.auth.dto.auth.PasswordResetRequestDTO;
import com.evecta.auth.dto.token.refresh.RefreshTokenRequestDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.config.SecurityConfig;
import com.evecta.auth.service.AuthService;
import com.evecta.auth.service.JwtService;
import com.evecta.auth.util.TestDataBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private ITokenRepository tokenRepository;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void login_web_conDatosValidos_retorna200YEstableceCookiesSinTokensBody() throws Exception {
        LoginRequestDTO request = TestDataBuilder.createLoginRequest("test@example.com", "TestPass123");
        AuthResponseDTO response = TestDataBuilder.createAuthResponseDTO();
        AuthService.LoginResult loginResult = new AuthService.LoginResult(
                response, "access-token-value", "refresh-token-value", "test@example.com", 1000L, 2000L);

        when(authService.login(any(LoginRequestDTO.class), anyString())).thenReturn(loginResult);

        mockMvc.perform(post("/auth/api/v1/login")
                        .header("X-Client-Origin", "web")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.roles").isArray())
                // Verificar que NO se exponen tokens en el body JSON
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }

    @Test
    void login_mobile_conDatosValidos_retornaTokensEnBodySinCookies() throws Exception {
        LoginRequestDTO request = TestDataBuilder.createLoginRequest("fiscalizador@test.com", "TestPass123");
        AuthResponseDTO response = AuthResponseDTO.builder()
                .email("fiscalizador@test.com")
                .name("Test")
                .lastname("User")
                .rut("12345678")
                .roles(List.of("USER_APP"))
                .authType("cookie")
                .build();
        AuthService.LoginResult loginResult = new AuthService.LoginResult(
                response, "mobile-access-token", "mobile-refresh-token", "fiscalizador@test.com", 1111L, 2222L);

        when(authService.login(any(LoginRequestDTO.class), anyString())).thenReturn(loginResult);

        mockMvc.perform(post("/auth/api/v1/login")
                        .header("X-Client-Origin", "mobile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                // App móvil no recibe cookies
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                // Los tokens viajan en el body (compatibilidad con SDK móvil)
                .andExpect(jsonPath("$.accessToken").value("mobile-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("mobile-refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.sub").value("fiscalizador@test.com"))
                .andExpect(jsonPath("$.iat").value(1111))
                .andExpect(jsonPath("$.exp").value(2222))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    void login_conPasswordIncorrecto_retorna401() throws Exception {
        LoginRequestDTO request = TestDataBuilder.createLoginRequest("test@example.com", "wrong");

        when(authService.login(any(LoginRequestDTO.class), anyString()))
                .thenThrow(new BadCredentialsException("Correo o contrase\u00f1a incorrectos"));

        mockMvc.perform(post("/auth/api/v1/login")
                        .header("X-Client-Origin", "mobile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_userAppDesdeWeb_retorna401() throws Exception {
        LoginRequestDTO request = TestDataBuilder.createLoginRequest("fiscalizador@test.com", "TestPass123");

        when(authService.login(any(LoginRequestDTO.class), anyString()))
                .thenThrow(new org.springframework.security.authentication.BadCredentialsException(
                        "No tienes permisos para acceder a esta plataforma administrativa."));

        mockMvc.perform(post("/auth/api/v1/login")
                        .header("X-Client-Origin", "web")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_conCookieValida_retorna200() throws Exception {
        Token validToken = TestDataBuilder.createToken(
                TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "test@example.com", "11111111", "1"),
                Token.TokenType.BEARER, false, false);
        when(tokenRepository.findByToken(anyString())).thenReturn(Optional.of(validToken));
        doNothing().when(authService).logout(anyString());

        mockMvc.perform(post("/auth/api/v1/logout")
                        .cookie(new jakarta.servlet.http.Cookie("access_token", "test-valid-token")))
                .andExpect(status().isOk());

        verify(authService).logout("test-valid-token");
    }

    @Test
    void logout_conHeaderAuthorization_retorna200() throws Exception {
        Token validToken = TestDataBuilder.createToken(
                TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "test@example.com", "11111111", "1"),
                Token.TokenType.BEARER, false, false);
        when(tokenRepository.findByToken(anyString())).thenReturn(Optional.of(validToken));
        doNothing().when(authService).logout(anyString());

        mockMvc.perform(post("/auth/api/v1/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer test-valid-token"))
                .andExpect(status().isOk());

        verify(authService).logout("test-valid-token");
    }

    @Test
    void validate_conTokenValido_retorna200() throws Exception {
        Token validToken = TestDataBuilder.createToken(
                TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "test@example.com", "11111111", "1"),
                Token.TokenType.BEARER, false, false);

        when(tokenRepository.findByToken(anyString())).thenReturn(Optional.of(validToken));

        mockMvc.perform(get("/auth/api/v1/validate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer test-valid-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }

    @Test
    void validate_conTokenInvalido_retorna403() throws Exception {
        when(jwtService.isTokenValid(anyString())).thenReturn(false);

        mockMvc.perform(get("/auth/api/v1/validate")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer test-invalid-token"))
                .andExpect(status().isForbidden());
    }

    @Test
    void refresh_conCookieValida_retorna200() throws Exception {
        AuthResponseDTO response = TestDataBuilder.createAuthResponseDTO();
        AuthService.RefreshResult refreshResult = new AuthService.RefreshResult(
                response, "new-access-token", "new-refresh-token", "test@example.com", 1000L, 2000L);

        when(authService.refresh(anyString())).thenReturn(refreshResult);

        mockMvc.perform(post("/auth/api/v1/refresh")
                        .cookie(new jakarta.servlet.http.Cookie("refresh_token", "test-refresh-token")))
                .andExpect(status().isOk())
                .andExpect(header().exists(HttpHeaders.SET_COOKIE))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.roles").isArray())
                // Verificar que NO se exponen tokens en el body JSON
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        verify(authService).refresh("test-refresh-token");
    }

    @Test
    void refresh_mobile_conBody_retornaTokensEnBody() throws Exception {
        RefreshTokenRequestDTO request = new RefreshTokenRequestDTO("test-refresh-token");
        AuthResponseDTO response = TestDataBuilder.createAuthResponseDTO();
        AuthService.RefreshResult refreshResult = new AuthService.RefreshResult(
                response, "new-mobile-access", "new-mobile-refresh", "test@example.com", 1000L, 2000L);

        when(authService.refresh(anyString())).thenReturn(refreshResult);

        mockMvc.perform(post("/auth/api/v1/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                // App móvil no recibe cookies
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                // Los tokens rotados viajan en el body
                .andExpect(jsonPath("$.accessToken").value("new-mobile-access"))
                .andExpect(jsonPath("$.refreshToken").value("new-mobile-refresh"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.sub").value("test@example.com"))
                .andExpect(jsonPath("$.iat").value(1000))
                .andExpect(jsonPath("$.exp").value(2000));

        verify(authService).refresh("test-refresh-token");
    }

    @Test
    void sessionStatus_conCookieValida_retornaSesionActiva() throws Exception {
        // Mock del servicio AuthService para /status
        com.evecta.auth.dto.auth.SessionStatusDTO.UserInfo userInfo =
                com.evecta.auth.dto.auth.SessionStatusDTO.UserInfo.builder()
                        .email("test@example.com")
                        .name("Test")
                        .roles(List.of("USER_ADMIN"))
                        .build();
        com.evecta.auth.dto.auth.SessionStatusDTO status =
                com.evecta.auth.dto.auth.SessionStatusDTO.builder()
                        .valid(true)
                        .user(userInfo)
                        .build();

        when(authService.validateSession(anyString())).thenReturn(status);

        mockMvc.perform(get("/auth/api/v1/status")
                        .cookie(new jakarta.servlet.http.Cookie("access_token", "test-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.user.email").value("test@example.com"));
    }

    @Test
    void recoveryRequest_conEmailValido_retorna200() throws Exception {
        PasswordRecoveryRequestDTO request = PasswordRecoveryRequestDTO.builder()
                .email("test@example.com")
                .build();

        doNothing().when(authService).initiatePasswordRecovery(anyString());

        mockMvc.perform(post("/auth/api/v1/recovery/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).initiatePasswordRecovery("test@example.com");
    }

    @Test
    void recoveryReset_conDatosValidos_retorna200() throws Exception {
        PasswordResetRequestDTO request = PasswordResetRequestDTO.builder()
                .email("test@example.com")
                .code("123456")
                .newPassword("NewPass123")
                .build();

        doNothing().when(authService).resetPassword(any(PasswordResetRequestDTO.class));

        mockMvc.perform(post("/auth/api/v1/recovery/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).resetPassword(any(PasswordResetRequestDTO.class));
    }

    @Test
    @WithMockUser(authorities = {"USER_APP"})
    void changePassword_conDatosValidos_retorna200() throws Exception {
        ChangePasswordRequestDTO request = ChangePasswordRequestDTO.builder()
                .oldPassword("OldPass123")
                .newPassword("NewPass456")
                .build();

        doNothing().when(authService).changePassword(anyString(), any(ChangePasswordRequestDTO.class));

        mockMvc.perform(post("/auth/api/v1/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).changePassword(anyString(), any(ChangePasswordRequestDTO.class));
    }
}
