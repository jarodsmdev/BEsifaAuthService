package com.evecta.auth.controller;

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
        public ResponseEntity<?> validate() {
                // si la peticion llega hasta aqui, si esta funcionando el
                // JwtAuthenticationFilter
                // valida el token y establece el SecurityContext.
                return ResponseEntity.ok(
                                Map.of(
                                                "message", "Token is valid"));
        }
}