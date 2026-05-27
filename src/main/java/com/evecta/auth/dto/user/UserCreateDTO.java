package com.evecta.auth.dto.user;

import com.evecta.auth.dto.RutValidator;
import com.evecta.auth.model.UserRole;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.*;

import java.time.LocalDate;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para la creación de un nuevo usuario.")
public class UserCreateDTO {
        @Schema(description = "RUT del usuario sin puntos ni guion", example = "12345678", required = true)
        @NotBlank(message = "RUT es obligatorio")
        @Pattern(regexp = "\\d{7,8}", message = "RUT debe tener 7 u 8 dígitos")
        private String rut;

        @Schema(description = "Dígito verificador del RUT", example = "K", required = true)
        @NotBlank(message = "DV es obligatorio")
        @Pattern(regexp = "^[0-9Kk]$", message = "DV debe ser número o K")
        private String dv;

        @Schema(description = "Nombre del usuario", example = "Juan", required = true)
        @NotBlank(message = "Nombre es obligatorio")
        @Size(min = 2, max = 50, message = "Nombre debe tener entre 2 y 50 caracteres")
        private String name;

        @Schema(description = "Apellido del usuario", example = "Pérez", required = true)
        @NotBlank(message = "Apellido es obligatorio")
        @Size(min = 2, max = 50, message = "Apellido debe tener entre 2 y 50 caracteres")
        private String lastName;

        @Schema(description = "Fecha de nacimiento del usuario", example = "1990-01-01")
        @Past(message = "La fecha de nacimiento debe ser pasada")
        private LocalDate birthDate;

        @Schema(description = "Email del usuario", example = "juan.perez@example.com", required = true)
        @NotBlank(message = "Email es obligatorio")
        @Email(message = "Email debe ser válido")
        @Pattern(regexp = "^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@" +
                        "(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)+" +
                        "[A-Za-z]{2,}$", message = "Email debe ser válido y no contener caracteres especiales no permitidos")
        private String email;

        @Schema(description = "Teléfono de contacto del usuario", example = "+56912345678")
        @Size(max = 20, message = "El teléfono no puede exceder los 20 caracteres")
        private String phone;

        @Schema(description = "Rol del usuario en el sistema", example = "USER_APP", required = true)
        @NotNull(message = "El rol es obligatorio")
        private UserRole role;

        @Schema(description = "Contraseña del usuario. Debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.", example = "Secreta123", required = true)
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
