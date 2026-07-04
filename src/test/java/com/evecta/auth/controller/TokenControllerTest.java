package com.evecta.auth.controller;

import com.evecta.auth.dto.token.TokenResponseDTO;
import com.evecta.auth.config.SecurityConfig;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.JwtService;
import com.evecta.auth.service.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.data.domain.PageImpl;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TokenController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
@WithMockUser(authorities = "USER_ADMIN")
class TokenControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private TokenService tokenService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private ITokenRepository tokenRepository;

    private TokenResponseDTO tokenResponseDTO() {
        return TokenResponseDTO.builder()
                .idToken(1L)
                .token("eyJhb***********")
                .tokenType("BEARER")
                .revoked(false)
                .expired(false)
                .expiresAt(LocalDateTime.now().plusHours(1))
                .createdAt(LocalDateTime.now())
                .modifiedAt(LocalDateTime.now())
                .userRut("11111111-1")
                .userEmail("test@example.com")
                .userName("Test")
                .userLastName("User")
                .build();
    }

    @Test
    void getAllTokens_retornaPagina200() throws Exception {
        Page<TokenResponseDTO> page = new PageImpl<>(List.of(tokenResponseDTO()));

        when(tokenService.findAllTokens(any())).thenReturn(page);

        mockMvc.perform(get("/auth/api/v1/tokens")
                        .param("page", "0")
                        .param("size", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content[0].idToken").value(1));
    }

    @Test
    void getTokenById_existente_retorna200() throws Exception {
        TokenResponseDTO response = tokenResponseDTO();

        when(tokenService.findTokenById(1L)).thenReturn(response);

        mockMvc.perform(get("/auth/api/v1/tokens/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idToken").value(1))
                .andExpect(jsonPath("$.userEmail").value("test@example.com"));
    }

    @Test
    void getTokenById_noExistente_retorna400() throws Exception {
        when(tokenService.findTokenById(anyLong()))
                .thenThrow(new IllegalArgumentException("Token no encontrado con ID: 999"));

        mockMvc.perform(get("/auth/api/v1/tokens/999"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getTokensByUserRut_retornaLista200() throws Exception {
        List<TokenResponseDTO> tokens = List.of(tokenResponseDTO());

        when(tokenService.findTokensByUserRut("11111111-1")).thenReturn(tokens);

        mockMvc.perform(get("/auth/api/v1/tokens/user/11111111-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].idToken").value(1))
                .andExpect(jsonPath("$[0].userRut").value("11111111-1"));
    }

    @Test
    void revokeToken_retorna200() throws Exception {
        TokenResponseDTO revoked = tokenResponseDTO();
        revoked.setRevoked(true);

        when(tokenService.revokeToken(1L)).thenReturn(revoked);

        mockMvc.perform(patch("/auth/api/v1/tokens/1/revoke"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idToken").value(1))
                .andExpect(jsonPath("$.revoked").value(true));
    }

    @Test
    void expireToken_retorna200() throws Exception {
        TokenResponseDTO expired = tokenResponseDTO();
        expired.setExpired(true);

        when(tokenService.expireToken(1L)).thenReturn(expired);

        mockMvc.perform(patch("/auth/api/v1/tokens/1/expire"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idToken").value(1))
                .andExpect(jsonPath("$.expired").value(true));
    }
}
