package com.evecta.auth.dto.user;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para la actualización de un usuario existente. Todos los campos son opcionales.")
public class UserUpdateDTO {

    @Schema(description = "Nuevo nombre del usuario", example = "Juanito")
    @Size(min = 2, max = 50, message = "Nombre debe tener entre 2 y 50 caracteres")
    private String name;

    @Schema(description = "Nuevo apellido del usuario", example = "Perez Gonzalez")
    @Size(min = 2, max = 50, message = "Apellido debe tener entre 2 y 50 caracteres")
    private String lastName;

    @Schema(description = "Nuevo email del usuario. Debe ser único.", example = "juanito.perez@example.com")
    @Email(message = "Debe ser un correo electrónico válido")
    private String email;

    @Schema(description = "Nuevo teléfono de contacto del usuario", example = "+56987654321")
    @Size(max = 20, message = "El teléfono no puede exceder los 20 caracteres")
    private String phone;

    @Schema(description = "Nueva contraseña del usuario. Si se provee, debe cumplir con los requisitos de seguridad.", example = "NuevaClave123")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    @jakarta.validation.constraints.Pattern(
        regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$",
        message = "La contraseña debe tener al menos una mayúscula, una minúscula y un número"
    )
    private String password;
}
