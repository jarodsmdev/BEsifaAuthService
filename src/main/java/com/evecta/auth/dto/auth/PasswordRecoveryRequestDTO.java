package com.evecta.auth.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para solicitar la recuperación de contraseña")
public class PasswordRecoveryRequestDTO {

    @Schema(description = "Correo electrónico institucional del usuario", example = "admin@sifa.cl", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El correo electrónico es obligatorio")
    @Email(message = "Debe ingresar un formato de correo válido")
    private String email;
}
