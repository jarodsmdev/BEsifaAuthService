package com.evecta.auth.security;

import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.util.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.evecta.auth.service.JwtService;

import java.io.IOException;
import java.util.List;

/**
 * Filtro de autenticación JWT que se ejecuta en cada petición.
 * 
 * Obtiene el token de:
 * 1. Cookie HttpOnly access_token (preferente para aplicaciones web)
 * 2. Header Authorization: Bearer <token> (fallback para apps móviles)
 * 
 * Valida el token en dos niveles:
 * - Firma y expiración (JwtService)
 * - Estado en base de datos (expirado/revocado)
 * 
 * Si es válido, establece el SecurityContext con el usuario y sus roles.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final ITokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Obtener token desde cookie httpOnly (preferente) o header Authorization (fallback)
        String token = CookieUtil.getAccessToken(request);

        if (token == null) {
            final String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }
        }

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            var storedToken = tokenRepository.findByToken(token).orElse(null);

            if (!jwtService.isTokenValid(token)) {
                SecurityContextHolder.clearContext();
            }

            if (storedToken == null || storedToken.isExpired() || storedToken.isRevoked()) {
                SecurityContextHolder.clearContext();
            } else {
                String username = jwtService.extractUsername(token);
                List<String> roles = jwtService.extractRoles(token);

                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                authorities
                        );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}