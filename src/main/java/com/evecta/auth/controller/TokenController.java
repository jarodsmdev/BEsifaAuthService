package com.evecta.auth.controller;

import java.util.List;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import com.evecta.auth.dto.token.TokenResponseDTO;
import com.evecta.auth.service.TokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth/api/v1/tokens")
@Tag(
    name = "Gestión de Tokens",
    description =
        "Endpoints para la administración y consulta de tokens JWT emitidos por el sistema")
@SecurityRequirement(name = "bearerAuth")
@RequiredArgsConstructor
@Slf4j
public class TokenController {

  private final TokenService tokenService;

  @Operation(
      summary = "Listar todos los tokens del sistema",
      description =
          "Retorna una lista paginada de todos los tokens JWT emitidos por el sistema, ordenados por fecha de creación descendente. Incluye información del token enmascarado, estado (revocado/expirado) y datos del usuario propietario.")
  @ApiResponse(
      responseCode = "200",
      description = "Lista paginada de tokens obtenida exitosamente",
      content =
          @Content(mediaType = "application/json", schema = @Schema(implementation = Page.class)))
  @ApiResponse(
      responseCode = "401",
      description = "No autorizado - Token JWT faltante, inválido o expirado",
      content = @Content(mediaType = "application/json"))
  @GetMapping
  public ResponseEntity<Page<TokenResponseDTO>> getAllTokens(
      @ParameterObject
          @PageableDefault(size = 20, sort = "idToken", direction = Sort.Direction.DESC)
          Pageable pageable) {
    log.info(
        "Recibida solicitud para listar tokens - página: {}, tamaño: {}",
        pageable.getPageNumber(),
        pageable.getPageSize());
    return ResponseEntity.ok(tokenService.findAllTokens(pageable));
  }

  @Operation(
      summary = "Obtener token por ID",
      description =
          "Retorna los detalles de un token específico identificado por su ID único. Incluye información del token enmascarado, estado y datos del usuario propietario.")
  @ApiResponse(
      responseCode = "200",
      description = "Token encontrado exitosamente",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = TokenResponseDTO.class),
              examples =
                  @ExampleObject(
                      value =
                          "{\n  \"idToken\": 1,\n  \"token\": \"eyJhb***********\",\n  \"tokenType\": \"ACCESS\",\n  \"revoked\": false,\n  \"expired\": false,\n  \"expiresAt\": \"2023-01-01T13:00:00\",\n  \"createdAt\": \"2023-01-01T12:00:00\",\n  \"modifiedAt\": \"2023-01-01T12:00:00\",\n  \"userRut\": \"12345678-9\",\n  \"userEmail\": \"usuario@ejemplo.com\",\n  \"userName\": \"Juan\",\n  \"userLastName\": \"Pérez\"\n}")))
  @ApiResponse(
      responseCode = "404",
      description =
          "Token no encontrado - El ID proporcionado no corresponde a ningún token en el sistema",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(value = "{\n  \"error\": \"Token no encontrado con ID: 999\"\n}")))
  @ApiResponse(
      responseCode = "401",
      description = "No autorizado - Token JWT faltante, inválido o expirado",
      content = @Content(mediaType = "application/json"))
  @Parameter(
      name = "id",
      description = "ID único del token a consultar",
      required = true,
      example = "1")
  @GetMapping("/{id}")
  public ResponseEntity<TokenResponseDTO> getTokenById(@PathVariable Long id) {
    log.info("Recibida solicitud de búsqueda de token por ID: {}", id);
    return ResponseEntity.ok(tokenService.findTokenById(id));
  }

  @Operation(
      summary = "Obtener tokens por RUT de usuario",
      description =
          "Retorna todos los tokens JWT asociados a un usuario específico identificado por su RUT. Útil para auditar las sesiones activas de un usuario.")
  @ApiResponse(
      responseCode = "200",
      description = "Lista de tokens del usuario obtenida exitosamente",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = TokenResponseDTO.class),
              examples =
                  @ExampleObject(
                      value =
                          "[\n  {\n    \"idToken\": 1,\n    \"token\": \"eyJhb***********\",\n    \"tokenType\": \"ACCESS\",\n    \"revoked\": false,\n    \"expired\": false,\n    \"expiresAt\": \"2023-01-01T13:00:00\",\n    \"createdAt\": \"2023-01-01T12:00:00\",\n    \"modifiedAt\": \"2023-01-01T12:00:00\",\n    \"userRut\": \"12345678-9\",\n    \"userEmail\": \"usuario@ejemplo.com\",\n    \"userName\": \"Juan\",\n    \"userLastName\": \"Pérez\"\n  }\n]")))
  @ApiResponse(
      responseCode = "401",
      description = "No autorizado - Token JWT faltante, inválido o expirado",
      content = @Content(mediaType = "application/json"))
  @Parameter(
      name = "rut",
      description = "RUT del usuario cuyos tokens se desean consultar (formato: 12345678-9)",
      required = true,
      example = "12345678-9")
  @GetMapping("/user/{rut}")
  public ResponseEntity<List<TokenResponseDTO>> getTokensByUserRut(@PathVariable String rut) {
    log.info("Recibida solicitud de búsqueda de tokens por RUT: {}", rut);
    return ResponseEntity.ok(tokenService.findTokensByUserRut(rut));
  }

  @Operation(
      summary = "Revocar token",
      description =
          "Invalida un token JWT específico marcándolo como revocado. Esta operación es irreversible y previene que el token sea utilizado en futuras peticiones. Solo puede revocarse tokens que estén activos (no expirados ni revocados previamente).")
  @ApiResponse(
      responseCode = "200",
      description = "Token revocado exitosamente",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = TokenResponseDTO.class),
              examples =
                  @ExampleObject(
                      value =
                          "{\n  \"idToken\": 1,\n  \"token\": \"eyJhb***********\",\n  \"tokenType\": \"ACCESS\",\n  \"revoked\": true,\n  \"expired\": false,\n  \"expiresAt\": \"2023-01-01T13:00:00\",\n  \"createdAt\": \"2023-01-01T12:00:00\",\n  \"modifiedAt\": \"2023-01-01T12:30:00\",\n  \"userRut\": \"12345678-9\",\n  \"userEmail\": \"usuario@ejemplo.com\",\n  \"userName\": \"Juan\",\n  \"userLastName\": \"Pérez\"\n}")))
  @ApiResponse(
      responseCode = "404",
      description =
          "Token no encontrado - El ID proporcionado no corresponde a ningún token en el sistema",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(value = "{\n  \"error\": \"Token no encontrado con ID: 999\"\n}")))
  @ApiResponse(
      responseCode = "400",
      description =
          "Solicitud inválida - El token ya se encuentra invalidado (expirado o revocado)",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(
                      value =
                          "{\n  \"error\": \"El token ya ha sido invalidado (expirado o revocado)\"\n}")))
  @ApiResponse(
      responseCode = "401",
      description = "No autorizado - Token JWT faltante, inválido o expirado",
      content = @Content(mediaType = "application/json"))
  @Parameter(
      name = "id",
      description = "ID único del token a revocar",
      required = true,
      example = "1")
  @PatchMapping("/{id}/revoke")
  public ResponseEntity<TokenResponseDTO> revokeToken(@PathVariable Long id) {
    log.info("Recibida solicitud de revocación de token ID: {}", id);
    return ResponseEntity.ok(tokenService.revokeToken(id));
  }

  @Operation(
      summary = "Expirar token",
      description =
          "Invalida un token JWT específico marcándolo como expirado. Esta operación es irreversible y previene que el token sea utilizado en futuras peticiones. Solo puede expirarse tokens que estén activos (no expirados ni revocados previamente).")
  @ApiResponse(
      responseCode = "200",
      description = "Token expirado exitosamente",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = TokenResponseDTO.class),
              examples =
                  @ExampleObject(
                      value =
                          "{\n  \"idToken\": 1,\n  \"token\": \"eyJhb***********\",\n  \"tokenType\": \"ACCESS\",\n  \"revoked\": false,\n  \"expired\": true,\n  \"expiresAt\": \"2023-01-01T13:00:00\",\n  \"createdAt\": \"2023-01-01T12:00:00\",\n  \"modifiedAt\": \"2023-01-01T12:30:00\",\n  \"userRut\": \"12345678-9\",\n  \"userEmail\": \"usuario@ejemplo.com\",\n  \"userName\": \"Juan\",\n  \"userLastName\": \"Pérez\"\n}")))
  @ApiResponse(
      responseCode = "404",
      description =
          "Token no encontrado - El ID proporcionado no corresponde a ningún token en el sistema",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(value = "{\n  \"error\": \"Token no encontrado con ID: 999\"\n}")))
  @ApiResponse(
      responseCode = "400",
      description =
          "Solicitud inválida - El token ya se encuentra invalidado (expirado o revocado)",
      content =
          @Content(
              mediaType = "application/json",
              examples =
                  @ExampleObject(
                      value =
                          "{\n  \"error\": \"El token ya ha sido invalidado (expirado o revocado)\"\n}")))
  @ApiResponse(
      responseCode = "401",
      description = "No autorizado - Token JWT faltante, inválido o expirado",
      content = @Content(mediaType = "application/json"))
  @Parameter(
      name = "id",
      description = "ID único del token a expirar",
      required = true,
      example = "1")
  @PatchMapping("/{id}/expire")
  public ResponseEntity<TokenResponseDTO> expireToken(@PathVariable Long id) {
    log.info("Recibida solicitud de expiración de token ID: {}", id);
    return ResponseEntity.ok(tokenService.expireToken(id));
  }
}
