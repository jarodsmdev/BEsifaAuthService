package com.evecta.auth.config;

import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.AuthService;
import com.evecta.auth.service.JwtService;
import com.evecta.auth.service.TokenService;
import com.evecta.auth.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"server.port=0"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private TokenService tokenService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private ITokenRepository tokenRepository;

    @Test
    @DisplayName("POST /auth/api/v1/login es público - retorna 400 por validación, no 401")
    void loginEndpoint_publico_retorna200() throws Exception {
        mockMvc.perform(post("/auth/api/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .header("X-Client-Origin", "test"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /auth/api/v1/refresh es público - retorna 200 sin auth")
    void refreshEndpoint_publico_retorna200() throws Exception {
        mockMvc.perform(post("/auth/api/v1/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /auth/api/v1/recovery/request es público - retorna 400 por validación, no 401")
    void recoveryEndpoint_publico_retorna200() throws Exception {
        mockMvc.perform(post("/auth/api/v1/recovery/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /auth/api/v1/users sin autenticación es rechazado")
    void userCreateEndpoint_sinAuth_retorna401() throws Exception {
        mockMvc.perform(post("/auth/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /auth/api/v1/tokens sin autenticación es rechazado")
    void tokenEndpoint_sinAuth_retorna401() throws Exception {
        mockMvc.perform(get("/auth/api/v1/tokens"))
                .andExpect(status().isForbidden());
    }
}
