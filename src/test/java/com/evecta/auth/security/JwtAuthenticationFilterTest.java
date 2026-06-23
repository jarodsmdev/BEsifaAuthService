package com.evecta.auth.security;

import com.evecta.auth.model.Token;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private ITokenRepository tokenRepository;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Token válido establece autenticación en SecurityContext")
    void doFilterInternal_tokenValido_estableceAutenticacion() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer valid-token");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        Token storedToken = mock(Token.class);
        when(storedToken.isExpired()).thenReturn(false);
        when(storedToken.isRevoked()).thenReturn(false);

        when(jwtService.extractUsername("valid-token")).thenReturn("test@example.com");
        when(jwtService.extractRoles("valid-token")).thenReturn(List.of("USER_ADMIN"));
        when(jwtService.isTokenValid("valid-token")).thenReturn(true);
        when(tokenRepository.findByToken("valid-token")).thenReturn(Optional.of(storedToken));

        filter.doFilterInternal(request, response, chain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo("test@example.com");
        assertThat(authentication.getAuthorities())
                .extracting("authority")
                .containsExactly("USER_ADMIN");

        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Token inválido según JWT limpia el contexto")
    void doFilterInternal_tokenInvalido_limpiaContexto() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid-token");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        when(jwtService.isTokenValid("invalid-token")).thenReturn(false);
        when(tokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Token sin storedToken (null) en BD limpia el contexto")
    void doFilterInternal_tokenNoEncontradoEnBD_limpiaContexto() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer token-not-in-db");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        when(jwtService.isTokenValid("token-not-in-db")).thenReturn(true);
        when(tokenRepository.findByToken("token-not-in-db")).thenReturn(Optional.empty());

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Token expirado en BD limpia el contexto")
    void doFilterInternal_tokenExpiradoEnBD_limpiaContexto() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer expired-token");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        Token storedToken = mock(Token.class);
        when(storedToken.isExpired()).thenReturn(true);

        when(jwtService.isTokenValid("expired-token")).thenReturn(true);
        when(tokenRepository.findByToken("expired-token")).thenReturn(Optional.of(storedToken));

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Token revocado en BD limpia el contexto")
    void doFilterInternal_tokenRevocadoEnBD_limpiaContexto() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer revoked-token");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        Token storedToken = mock(Token.class);
        when(storedToken.isExpired()).thenReturn(false);
        when(storedToken.isRevoked()).thenReturn(true);

        when(jwtService.isTokenValid("revoked-token")).thenReturn(true);
        when(tokenRepository.findByToken("revoked-token")).thenReturn(Optional.of(storedToken));

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Sin header Authorization no procesa el token")
    void doFilterInternal_sinHeader_noProcesa() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verifyNoInteractions(jwtService);
        verifyNoInteractions(tokenRepository);
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Header sin prefijo Bearer no procesa el token")
    void doFilterInternal_headerSinBearer_noProcesa() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic xxx");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verifyNoInteractions(jwtService);
        verifyNoInteractions(tokenRepository);
        verify(chain).doFilter(request, response);
    }

    @Test
    @DisplayName("Excepción durante el procesamiento limpia el contexto")
    void doFilterInternal_excepcion_limpiaContexto() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer problematic-token");
        var response = new MockHttpServletResponse();
        var chain = mock(FilterChain.class);

        when(tokenRepository.findByToken("problematic-token")).thenThrow(new RuntimeException("DB error"));

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }
}
