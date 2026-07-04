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
@Schema(description = "Objeto de transferencia de datos para la solicitud de inicio de sesión")
public class LoginRequestDTO {

    @Schema(description = "Correo electrónico del usuario", example = "usuario@prueba.com", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Email es obligatorio")
    @Email(message = "Email debe ser valido")
    private String email;

    @Schema(description = "Contraseña del usuario", example = "Usuario123", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "Contrasena es obligatoria")
    private String password;
}
