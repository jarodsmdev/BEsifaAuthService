package com.evecta.auth.dto.user;

import com.evecta.auth.model.UserEntity;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "DTO para la respuesta de un usuario. Contiene los datos públicos del usuario.")
public class UserResponseDTO {

    @Schema(description = "RUT del usuario", example = "12345678")
    private String rut;

    @Schema(description = "Dígito verificador del RUT", example = "K")
    private String dv;

    @Schema(description = "Nombre del usuario", example = "Juan")
    private String name;

    @Schema(description = "Apellido del usuario", example = "Pérez")
    private String lastName;

    @Schema(description = "Fecha de nacimiento del usuario", example = "1990-01-01")
    private LocalDate birthDate;

    @Schema(description = "Email del usuario", example = "juan.perez@example.com")
    private String email;

    @Schema(description = "Teléfono de contacto del usuario", example = "+56912345678")
    private String phone;

    @Schema(description = "Rol del usuario en el sistema", example = "USER_APP")
    private String role;

    @Schema(description = "Indica si el usuario está activo en el sistema", example = "true")
    private boolean isActive;

    @Schema(description = "Fecha y hora de creación del usuario", example = "2023-01-01T12:00:00")
    private LocalDateTime createdAt;

    @Schema(description = "Fecha y hora de la última modificación del usuario", example = "2023-01-02T18:30:00")
    private LocalDateTime modifiedAt;

    // Método de fábrica para crear desde Entity
    public static UserResponseDTO fromEntity(UserEntity user) {
        return UserResponseDTO.builder()
                .rut(user.getRut())
                .dv(user.getDv())
                .name(user.getName())
                .lastName(user.getLastName())
                .birthDate(user.getBirthDate())
                .email(user.getEmail())
                .phone(user.getPhone())
                .role(user.getRole().name())
                .isActive(user.isActive())
                .createdAt(user.getCreatedAt())
                .modifiedAt(user.getModifiedAt())
                .build();
    }
}