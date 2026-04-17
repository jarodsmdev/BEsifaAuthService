package com.evecta.auth.dto.auth;

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
public class LoginRequestDTO {

    @NotBlank(message = "Email es obligatorio")
    @Email(message = "Email debe ser valido")
    private String email;

    @NotBlank(message = "Contrasena es obligatoria")
    private String password;
}
