package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import com.evecta.auth.dto.token.TokenResponseDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.util.TestDataBuilder;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private ITokenRepository tokenRepository;

    @InjectMocks
    private TokenService tokenService;

    private UserEntity user;
    private Token validToken;
    private Token revokedToken;

    @BeforeEach
    void setUp() {
        user = TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "test@example.com", "11111111", "1");
        validToken = TestDataBuilder.createToken(user, Token.TokenType.BEARER, false, false);
        validToken.setIdToken(1L);
        revokedToken = TestDataBuilder.createToken(user, Token.TokenType.BEARER, true, true);
        revokedToken.setIdToken(2L);
    }

    @Test
    void findAllTokens_retornaPagina() {
        Pageable pageable = PageRequest.of(0, 10);
        Page<Token> tokenPage = new PageImpl<>(List.of(validToken));
        when(tokenRepository.findAllByOrderByIdTokenDesc(pageable)).thenReturn(tokenPage);

        Page<TokenResponseDTO> result = tokenService.findAllTokens(pageable);

        assertNotNull(result);
        assertEquals(1, result.getContent().size());
    }

    @Test
    void findTokenById_existente_retornaDTO() {
        when(tokenRepository.findById(1L)).thenReturn(Optional.of(validToken));

        TokenResponseDTO result = tokenService.findTokenById(1L);

        assertNotNull(result);
        assertEquals(1L, result.getIdToken());
    }

    @Test
    void findTokenById_noExistente_lanzaExcepcion() {
        when(tokenRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () -> tokenService.findTokenById(99L));
    }

    @Test
    void revokeToken_valido_revoca() {
        when(tokenRepository.findById(1L)).thenReturn(Optional.of(validToken));
        when(tokenRepository.save(any(Token.class))).thenAnswer(inv -> inv.getArgument(0));

        TokenResponseDTO result = tokenService.revokeToken(1L);

        assertNotNull(result);
        assertTrue(result.isRevoked());
    }

    @Test
    void revokeToken_yaRevocado_lanzaExcepcion() {
        when(tokenRepository.findById(2L)).thenReturn(Optional.of(revokedToken));

        assertThrows(IllegalStateException.class, () -> tokenService.revokeToken(2L));
    }

    @Test
    void expireToken_valido_expiro() {
        when(tokenRepository.findById(1L)).thenReturn(Optional.of(validToken));
        when(tokenRepository.save(any(Token.class))).thenAnswer(inv -> inv.getArgument(0));

        TokenResponseDTO result = tokenService.expireToken(1L);

        assertNotNull(result);
        assertTrue(result.isExpired());
    }

    @Test
    void generateRefreshToken_retornaString() {
        String refreshToken = tokenService.generateRefreshToken();

        assertNotNull(refreshToken);
        assertFalse(refreshToken.isEmpty());
    }
}
