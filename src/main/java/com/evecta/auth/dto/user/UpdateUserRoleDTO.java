package com.evecta.auth.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Estructura requerida para actualizar el rol de un usuario en el sistema")
public class UpdateUserRoleDTO {

  @Schema(
      description =
          "Nombre del nuevo rol asignado al usuario. Debe coincidir exactamente con los ENUMs del sistema.",
      example = "USER_ADMIN",
      requiredMode = Schema.RequiredMode.REQUIRED)
  @NotBlank(message = "El campo 'role' es obligatorio y no puede estar vacío")
  private String role;
}
