package com.evecta.auth.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth/api/v1")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

        private final AuthService authService;
        private final ITokenRepository tokenRepository;

        // LOGIN
        @PostMapping("/login")
        public ResponseEntity<AuthResponseDTO> login(
                        @Valid @RequestBody LoginRequestDTO loginRequest) {

                log.info("Login request: {}", loginRequest.getEmail());

                return ResponseEntity.ok(authService.login(loginRequest));
        }

        // LOGOUT
        @PostMapping("/logout")
        public ResponseEntity<?> logout(
                        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        return ResponseEntity.badRequest().body(
                                        Map.of(
                                                        "error", "Authorization header inválido"));
                }

                authService.logout(authHeader);

                return ResponseEntity.ok(
                                Map.of(
                                                "message", "Logout successful"));
        }

        // VALIDATE SESSION
        @GetMapping("/validate")
        public ResponseEntity<?> validate(
                        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {

                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                        return ResponseEntity.badRequest().body(
                                        Map.of(
                                                        "valid", false,
                                                        "error", "Authorization header inválido o ausente"));
                }

                String token = authHeader.substring(7);

                var storedToken = tokenRepository.findByToken(token).orElse(null);

                if (storedToken == null) {
                        return ResponseEntity.ok(
                                        Map.of(
                                                        "valid", false,
                                                        "error", "Token no encontrado en la base de datos"));
                }

                if (storedToken.isExpired()) {
                        return ResponseEntity.ok(
                                        Map.of(
                                                        "valid", false,
                                                        "error", "Token ha expirado",
                                                        "expired", true));
                }

                if (storedToken.isRevoked()) {
                        return ResponseEntity.ok(
                                        Map.of(
                                                        "valid", false,
                                                        "error", "Token ha sido revocado",
                                                        "revoked", true));
                }

                return ResponseEntity.ok(
                                Map.of(
                                                "valid", true,
                                                "message", "Token es válido",
                                                "user", storedToken.getUser().getEmail(),
                                                "roles", resolveRoles(storedToken.getUser())));
        }

        private List<String> resolveRoles(UserEntity user) {
                List<String> roles = new ArrayList<>();
                if (user.getRole() == UserRole.USER_APP) {
                        roles.add("USER_APP");
                }
                if (user.getRole() == UserRole.USER_JPL) {
                        roles.add("USER_JPL");
                }
                if (user.getRole() == UserRole.USER_SUPERVISOR) {
                        roles.add("USER_SUPERVISOR");
                }
                if (user.getRole() == UserRole.USER_ADMIN) {
                        roles.add("USER_ADMIN");
                }
                return roles;
        }
}