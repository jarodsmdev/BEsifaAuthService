package com.evecta.auth.dto.auth;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la respuesta del endpoint de verificación de sesión (/status).
 * Permite al frontend verificar si la sesión actual es válida sin exponer tokens.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Estado de la sesión del usuario")
public class SessionStatusDTO {

    @Schema(description = "Indica si la sesión es válida", example = "true")
    private boolean valid;

    @Schema(description = "Información del usuario autenticado (null si no hay sesión válida)")
    private UserInfo user;

    @Schema(description = "Mensaje de error si la sesión no es válida", example = "Sesión expirada")
    private String error;

    /**
     * Información básica del usuario extraída del token.
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "Información básica del usuario")
    public static class UserInfo {

        @Schema(description = "Email del usuario", example = "usuario@example.com")
        private String email;

        @Schema(description = "Nombre del usuario", example = "Juan")
        private String name;

        @Schema(description = "Apellido del usuario", example = "Pérez")
        private String lastname;

        @Schema(description = "RUT del usuario", example = "12345678-9")
        private String rut;

        @Schema(description = "Roles del usuario", example = "[\"USER_ADMIN\"]")
        private List<String> roles;
    }
}
