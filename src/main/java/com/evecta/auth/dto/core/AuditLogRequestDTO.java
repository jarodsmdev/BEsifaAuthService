package com.evecta.auth.dto.core;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para el registro de un log de auditoría en el core service")
public class AuditLogRequestDTO {
    @Schema(description = "Email del usuario", example = "nico@gmail.com")
    private String emailUsuario;

    @Schema(description = "Acción que realizó el usuario", example = "Inicio de sesión")
    private String accion;

    @Schema(description = "Detalles de la acción ejecutada encapsulada en un objeto JSON", example = "{}")
    private Object detalles;
}
