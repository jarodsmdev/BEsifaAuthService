package com.evecta.auth.dto.auth;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la respuesta de autenticación de clientes NO basados en navegador
 * (app móvil nativa). A diferencia del navegador, una app móvil no puede
 * utilizar cookies HttpOnly, por lo que recibe los tokens en el body JSON.
 * 
 * Los campos replican la respuesta original del backend para mantener
 * compatibilidad con el SDK móvil existente.
 * 
 * @see com.evecta.auth.util.CookieUtil para el manejo de cookies (web)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Objeto de transferencia de datos para la respuesta de autenticación de clientes móviles (tokens en el body)")
public class MobileAuthResponseDTO {

    @Schema(description = "Token de acceso JWT", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String accessToken;

    @Schema(description = "Refresh Token", example = "VZqY...")
    private String refreshToken;

    @Schema(description = "Tipo de token", example = "Bearer")
    private String tokenType;

    @Schema(description = "Asunto del token (generalmente el ID o email del usuario)", example = "usuario@evecta.com")
    private String sub;

    @Schema(description = "Timestamp de la emisión del token (epoch seconds)", example = "1678886400")
    private Long iat;

    @Schema(description = "Timestamp de la expiración del token (epoch seconds)", example = "1678890000")
    private Long exp;

    @Schema(description = "Lista de roles asignados al usuario", example = "[\"USER_APP\"]")
    private List<String> roles;
}