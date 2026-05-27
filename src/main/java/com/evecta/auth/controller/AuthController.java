package com.evecta.auth.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.dto.token.refresh.RefreshTokenRequestDTO;
import com.evecta.auth.dto.token.refresh.RefreshTokenResponseDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth/api/v1")
@Tag(
    name = "Autenticación",
    description = "Endpoints perimetrales para autenticación y manejo de sesiones JWT")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final ITokenRepository tokenRepository;

    // LOGIN
    @Operation(
            summary = "Iniciar sesión",
            description = "Autentica un usuario y retorna access token + refresh token")
    @ApiResponse(
            responseCode = "200",
            description = "Login exitoso",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthResponseDTO.class)
            )
    )
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO loginRequest) {

        log.info("Login request: {}", loginRequest.getEmail());

        return ResponseEntity.ok(authService.login(loginRequest));
    }

    // LOGOUT
    @Operation(
            summary = "Cerrar sesión",
            description = "Revoca el token actual",
            security = @SecurityRequirement(name = "bearerAuth"))
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @Parameter(
                    description = "JWT Bearer Token",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
            String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.info("Logout fallido: Authorization header inválido");
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Authorization header inválido"));
        }

        log.info("Logout request");
        authService.logout(authHeader);

        log.info("Logout exitoso");
        return ResponseEntity.ok(
                Map.of("message", "Logout successful"));
    }

    // VALIDATE SESSION
    @Operation(
            summary = "Validar token",
            description = "Valida si el token JWT es válido, no expirado y no revocado",
            security = @SecurityRequirement(name = "bearerAuth"))
    @GetMapping("/validate")
    public ResponseEntity<?> validate(
            @Parameter(
                    description = "JWT Bearer Token",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
            String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.info("Validación fallida: Authorization header inválido o ausente");
            return ResponseEntity.badRequest().body(
                    Map.of(
                            "valid", false,
                            "error", "Authorization header inválido o ausente"));
        }

        String token = authHeader.substring(7);
        log.info("Validación de token solicitada");

        var storedToken = tokenRepository.findByToken(token).orElse(null);

        if (storedToken == null) {
            log.info("Token no encontrado en base de datos");
            return ResponseEntity.ok(
                    Map.of(
                            "valid", false,
                            "error", "Token no encontrado"));
        }

        if (storedToken.isExpired()) {
            log.info("Token expirado: {}", storedToken.getUser().getEmail());
            return ResponseEntity.ok(
                    Map.of(
                            "valid", false,
                            "error", "Token expirado",
                            "expired", true));
        }

        if (storedToken.isRevoked()) {
            log.info("Token revocado: {}", storedToken.getUser().getEmail());
            return ResponseEntity.ok(
                    Map.of(
                            "valid", false,
                            "error", "Token revocado",
                            "revoked", true));
        }

        log.info("Token válido para usuario: {}", storedToken.getUser().getEmail());
        return ResponseEntity.ok(
                Map.of(
                        "valid", true,
                        "message", "Token válido",
                        "user", storedToken.getUser().getEmail(),
                        "roles", resolveRoles(storedToken.getUser())));
    }

    // REFRESH TOKEN
    @Operation(
            summary = "Renovar access token",
            description = "Genera un nuevo access token usando un refresh token válido")
    @ApiResponse(
            responseCode = "200",
            description = "Token renovado correctamente",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = RefreshTokenResponseDTO.class)
            )
    )
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refresh(
            @RequestBody RefreshTokenRequestDTO request) {

        log.info("Refresh token solicitado");
        var response = authService.refresh(request.refreshToken());
        log.info("Refresh token exitoso");
        return ResponseEntity.ok(response);
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