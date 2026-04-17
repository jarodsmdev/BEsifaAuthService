package com.evecta.auth.dto.user;

import com.evecta.auth.model.UserEntity;
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
public class UserResponseDTO {

    private String rut;
    private String dv;
    private String name;
    private String lastName;
    private LocalDate birthDate;
    private String email;
    private String role;
    private boolean isActive;
    private LocalDateTime createdAt;
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
                .role(user.getRole().name())
                .isActive(user.isActive())
                .createdAt(user.getCreatedAt())
                .modifiedAt(user.getModifiedAt())
                .build();
    }
}