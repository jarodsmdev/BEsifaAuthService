package com.evecta.auth.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para restablecer la contraseña usando el código de verificación")
public class PasswordResetRequestDTO {

    @Schema(description = "Correo electrónico del usuario", example = "admin@sifa.cl", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El correo electrónico es obligatorio")
    @Email(message = "Debe ingresar un formato de correo válido")
    private String email;

    @Schema(description = "Código de verificación de 6 dígitos enviado por correo", example = "123456", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "El código es obligatorio")
    @Size(min = 6, max = 6, message = "El código debe tener exactamente 6 caracteres")
    private String code;

    @Schema(description = "Nueva contraseña para el usuario", example = "NuevaContra123", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "La nueva contraseña es obligatoria")
    @Size(min = 8, message = "La nueva contraseña debe tener al menos 8 caracteres")
    private String newPassword;
}
