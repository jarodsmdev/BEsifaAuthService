package com.evecta.auth.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
    description =
        "Endpoints perimetrales para la generación, validación y revocación de sesiones de usuarios")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

  private final AuthService authService;
  private final ITokenRepository tokenRepository;

  // LOGIN
  @Operation(
      summary = "Iniciar Sesión en el ecosistema SIFA",
      description =
          "Valida las credenciales del usuario (Email y Contraseña). Si son correctas, genera un JSON Web Token (JWT) firmado con algoritmo HMAC-SHA que debe adjuntarse en las cabeceras subsecuentes.")
  @ApiResponse(
      responseCode = "200",
      description = "Autenticación exitosa. Se retorna el token y los datos del perfil.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = AuthResponseDTO.class)))
  @ApiResponse(
      responseCode = "401",
      description =
          "Credenciales inválidas (Usuario o contraseña incorrectos) o cuenta deshabilitada/revocada administrativamente.",
      content = @Content(mediaType = "application/json"))
  @ApiResponse(
      responseCode = "400",
      description = "Payload de entrada malformado o campos obligatorios faltantes.",
      content = @Content(mediaType = "application/json"))
  @PostMapping("/login")
  public ResponseEntity<AuthResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequest) {

    log.info("Login request: {}", loginRequest.getEmail());

    return ResponseEntity.ok(authService.login(loginRequest));
  }

  // LOGOUT
  @Operation(
      summary = "Cerrar Sesión en el ecosistema SIFA",
      description =
          "Revoca el token JWT actual del usuario, invalidándolo para futuras peticiones. Requiere que se envíe el token en la cabecera Authorization.",
      security = @SecurityRequirement(name = "bearerAuth"))
  @ApiResponse(
      responseCode = "200",
      description = "Sesión cerrada correctamente y token revocado.",
      content =
          @Content(
              mediaType = "application/json",
              examples = @ExampleObject(value = "{\n  \"message\": \"Logout successful\"\n}")))
  @ApiResponse(
      responseCode = "400",
      description = "Cabecera de autorización inválida o ausente, o el token ya está invalidado.",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(value = "{\n  \"error\": \"Authorization header inválido\"\n}")))
  @PostMapping("/logout")
  public ResponseEntity<?> logout(
      @Parameter(
              description = "Token JWT de tipo Bearer",
              required = true,
              example = "Bearer eyJhbGciOiJIUzI1NiIsInR5c...")
          @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
          String authHeader) {

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return ResponseEntity.badRequest().body(Map.of("error", "Authorization header inválido"));
    }

    try {
      authService.logout(authHeader);
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    } catch (IllegalStateException e) {
      return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    return ResponseEntity.ok(Map.of("message", "Logout successful"));
  }

  // VALIDATE SESSION
  @Operation(
      summary = "Validar el estado del Token JWT",
      description =
          "Verifica si el token proporcionado en la cabecera es válido, no ha expirado y no ha sido revocado. Retorna los datos básicos de la sesión (usuario y roles) si es válido.",
      security = @SecurityRequirement(name = "bearerAuth"))
  @ApiResponse(
      responseCode = "200",
      description =
          "Retorna el estado de validación del token. Puede indicar si es válido, expirado o revocado.",
      content =
          @Content(
              mediaType = "application/json",
              examples = {
                @ExampleObject(
                    name = "Token Válido",
                    value =
                        "{\n  \"valid\": true,\n  \"message\": \"Token es válido\",\n  \"user\": \"usuario@ejemplo.com\",\n  \"roles\": [\"USER_APP\"]\n}"),
                @ExampleObject(
                    name = "Token Expirado",
                    value =
                        "{\n  \"valid\": false,\n  \"error\": \"Token ha expirado\",\n  \"expired\": true\n}"),
                @ExampleObject(
                    name = "Token Revocado",
                    value =
                        "{\n  \"valid\": false,\n  \"error\": \"Token ha sido revocado\",\n  \"revoked\": true\n}"),
                @ExampleObject(
                    name = "Token No Encontrado",
                    value =
                        "{\n  \"valid\": false,\n  \"error\": \"Token no encontrado en la base de datos\"\n}")
              }))
  @ApiResponse(
      responseCode = "400",
      description = "Cabecera de autorización inválida o ausente.",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(
                      value =
                          "{\n  \"valid\": false,\n  \"error\": \"Authorization header inválido o ausente\"\n}")))
  @GetMapping("/validate")
  public ResponseEntity<?> validate(
      @Parameter(
              description = "Token JWT de tipo Bearer",
              required = true,
              example = "Bearer eyJhbGciOiJIUzI1NiIsInR5c...")
          @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
          String authHeader) {

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return ResponseEntity.badRequest()
          .body(Map.of("valid", false, "error", "Authorization header inválido o ausente"));
    }

    String token = authHeader.substring(7);

    var storedToken = tokenRepository.findByToken(token).orElse(null);

    if (storedToken == null) {
      return ResponseEntity.ok(
          Map.of("valid", false, "error", "Token no encontrado en la base de datos"));
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
            "valid",
            true,
            "message",
            "Token es válido",
            "user",
            storedToken.getUser().getEmail(),
            "roles",
            resolveRoles(storedToken.getUser())));
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
