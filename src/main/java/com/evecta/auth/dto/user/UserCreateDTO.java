package com.evecta.auth.dto.user;

import com.evecta.auth.dto.RutValidator;
import jakarta.validation.constraints.*;
import lombok.*;

import java.time.LocalDate;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCreateDTO {
        @NotBlank(message = "RUT es obligatorio")
        @Pattern(regexp = "\\d{7,8}", message = "RUT debe tener 7 u 8 dígitos")
        private String rut;

        @NotBlank(message = "DV es obligatorio")
        @Pattern(regexp = "^[0-9Kk]$", message = "DV debe ser número o K")
        private String dv;

        @NotBlank(message = "Nombre es obligatorio")
        @Size(min = 2, max = 50, message = "Nombre debe tener entre 2 y 50 caracteres")
        private String name;

        @NotBlank(message = "Apellido es obligatorio")
        @Size(min = 2, max = 50, message = "Apellido debe tener entre 2 y 50 caracteres")
        private String lastName;

        @Past(message = "La fecha de nacimiento debe ser pasada")
        private LocalDate birthDate;

        @NotBlank(message = "Email es obligatorio")
        @Email(message = "Email debe ser válido")
        @Pattern(regexp = "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@" +
                        "(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+" +
                        "[A-Za-z]{2,}$", message = "Email debe ser válido y no contener caracteres especiales no permitidos")
        private String email;

        @Size(max = 20, message = "El teléfono no puede exceder los 20 caracteres")
        private String phone;

        // @NotNull(message = "El rol es obligatorio")
        // private UserRole role;

        @NotBlank(message = "Contraseña es obligatoria")
        @Size(min = 8, message = "Contraseña debe tener al menos 8 caracteres")
        @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).*$", message = "La contraseña debe tener al menos una mayúscula, una minúscula y un número")
        private String password;

        // Validación personalizada a nivel de clase
        @AssertTrue(message = "RUT inválido")
        public boolean isRutValido() {
                return RutValidator.validarRut(this.rut, this.dv);
        }
}
