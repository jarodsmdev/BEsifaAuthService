package com.evecta.auth.dto.auth;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Objeto de transferencia de datos para la respuesta de autenticación")
public class AuthResponseDTO {

    @Schema(description = "Token de acceso JWT", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    private String accessToken;

    @Schema(description = "Refresh Token")
    private String refreshToken;

    @Schema(description = "Tipo de token", example = "Bearer")
    private String tokenType;

    @Schema(description = "Asunto del token (generalmente el ID o email del usuario)", example = "usuario@evecta.com")
    private String sub;

    @Schema(description = "Timestamp de la emisión del token (epoch seconds)", example = "1678886400")
    private Long iat;

    @Schema(description = "Timestamp de la expiración del token (epoch seconds)", example = "1678890000")
    private Long exp;

    @Schema(description = "Lista de roles asignados al usuario", example = "[\"USER_APP\", \"USER_ADMIN\"]")
    private List<String> roles;

    @Schema(description = "Lista de permisos específicos del usuario", example = "[]")
    private List<String> permisos;
}
