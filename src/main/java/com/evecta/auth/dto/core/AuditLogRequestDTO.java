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

  @Schema(description = "Nombre de la tabla afectada en la BD", example = "users", nullable = true)
  private String tablaAfectada;

  @Schema(
      description = "ID o RUT del registro que fue modificado",
      example = "19234567-8",
      nullable = true)
  private String idRegistroAfectado;

  @Schema(
      description = "Detalles de la acción ejecutada encapsulada en un objeto JSON",
      example = "{}")
  private Object detalles;
}
