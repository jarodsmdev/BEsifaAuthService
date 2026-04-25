package com.evecta.auth.dto.user;

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
public class UserUpdateDTO {

    @Size(min = 2, max = 50, message = "Nombre debe tener entre 2 y 50 caracteres")
    private String name;

    @Size(min = 2, max = 50, message = "Apellido debe tener entre 2 y 50 caracteres")
    private String lastName;

    @Email(message = "Debe ser un correo electrónico válido")
    private String email;

    @Size(max = 20, message = "El teléfono no puede exceder los 20 caracteres")
    private String phone;

    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    @jakarta.validation.constraints.Pattern(
        regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$",
        message = "La contraseña debe tener al menos una mayúscula, una minúscula y un número"
    )
    private String password;
}
