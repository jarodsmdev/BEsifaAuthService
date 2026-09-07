package com.evecta.auth.config;

import com.evecta.auth.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import org.springframework.http.HttpMethod;

import java.util.Arrays;
import java.util.List;

/**
 * Configuración de seguridad Spring.
 * 
 * Arquitectura:
 * - Autenticación basada en tokens JWT en cookies HttpOnly
 * - CSRF deshabilitado (protegido por SameSite=Strict en las cookies)
 * - CORS habilitado con allowCredentials(true) para permitir cookies
 * - Endpoints públicos: login, refresh, status, recovery, swagger
 * 
 * Endpoint /status se mantiene público ya que el frontend lo usa
 * para verificar la sesión sin tener acceso directo al token.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // Mapea el JSON/YAML base autogenerado por SpringDoc
                        .requestMatchers("/v3/api-docs").permitAll()
                        .requestMatchers("/v3/api-docs/**").permitAll()
                        // Mapea la interfaz gráfica en caso de que desees consultarla localmente
                        .requestMatchers("/swagger-ui.html").permitAll()
                        .requestMatchers("/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/api/v1/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/api/v1/refresh").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/api/v1/recovery/**").permitAll()
                        // El frontend consulta el estado de la sesión sin token explícito (usa cookie)
                        .requestMatchers(HttpMethod.GET, "/auth/api/v1/status").permitAll()
                        // Solo los ADMIN pueden crear, borrar o cambiar roles
                        .requestMatchers(HttpMethod.POST, "/auth/api/v1/users").hasAuthority("USER_ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/auth/api/v1/users").hasAuthority("USER_ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/auth/api/v1/users/*/role").hasAuthority("USER_ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/auth/api/v1/users/*/activate").hasAuthority("USER_ADMIN")
                        // Solo ADMIN pueden gestionar tokens
                        .requestMatchers(HttpMethod.GET, "/auth/api/v1/tokens/**").hasAuthority("USER_ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/auth/api/v1/tokens/**").hasAuthority("USER_ADMIN")
                        // Cualquier usuario autenticado puede ver la lista
                        .anyRequest().authenticated())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Configuración CORS.
     * 
     * allowCredentials(true) es REQUERIDO para que las cookies HttpOnly
     * se envíen en peticiones cross-origin. Cuando se usan credenciales,
     * no se puede usar "*" como origen: se debe listar explícitamente.
     * 
     * @return Fuente de configuración CORS
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Orígenes permitidos (no se puede usar "*" con allowCredentials=true)
        configuration.setAllowedOrigins(List.of(
                "https://sifacore.netlify.app",
                "https://sifacore2.netlify.app",
                "http://localhost:5173",
                "http://localhost:3000",
                "http://sifacore.s3-website-us-east-1.amazonaws.com",
                "https://sifacore.s3.us-east-1.amazonaws.com"));
        // Permitir credenciales (cookies) en peticiones cross-origin
        configuration.setAllowCredentials(true);
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        // Exponer Set-Cookie para que el navegador guarde las cookies
        configuration.setExposedHeaders(List.of("Set-Cookie"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}