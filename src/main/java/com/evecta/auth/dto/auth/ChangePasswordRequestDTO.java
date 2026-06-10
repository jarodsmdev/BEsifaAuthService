package com.evecta.auth.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para cambiar la contraseña estando autenticado")
public class ChangePasswordRequestDTO {

    @Schema(description = "Contraseña actual del usuario", example = "Secreta123", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank(message = "La contraseña actual es obligatoria")
    private String oldPassword;

    @Schema(
        description = "Nueva contraseña. Debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.",
        example = "NuevaClave456",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    @NotBlank(message = "La nueva contraseña es obligatoria")
    @Size(min = 8, message = "La nueva contraseña debe tener al menos 8 caracteres")
    @Pattern(
        regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$",
        message = "La nueva contraseña debe tener al menos una mayúscula, una minúscula y un número"
    )
    private String newPassword;
}
