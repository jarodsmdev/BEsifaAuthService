package com.evecta.auth.dto.auth;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la respuesta de autenticación.
 * 
 * NOTA: Los tokens (accessToken, refreshToken) ya NO se retornan en el body JSON.
 * Ahora se establecen como cookies HttpOnly en los headers de respuesta.
 * Este DTO contiene solo la información del usuario para el frontend.
 * 
 * @see com.evecta.auth.util.CookieUtil para manejo de cookies
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Objeto de transferencia de datos para la respuesta de autenticación")
public class AuthResponseDTO {

    @Schema(description = "Email del usuario autenticado", example = "usuario@evecta.com")
    private String email;

    @Schema(description = "Nombre del usuario", example = "Juan")
    private String name;

    @Schema(description = "Apellido del usuario", example = "Pérez")
    private String lastname;

    @Schema(description = "RUT del usuario", example = "12345678-9")
    private String rut;

    @Schema(description = "Lista de roles asignados al usuario", example = "[\"USER_ADMIN\"]")
    private List<String> roles;

    @Schema(description = "Tipo de autenticación", example = "cookie")
    private String authType;
}
