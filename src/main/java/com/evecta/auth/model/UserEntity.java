package com.evecta.auth.model;

import com.evecta.auth.dto.RutValidator;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users")
@Setter @Getter @Builder
@NoArgsConstructor @AllArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID userId;

    @NotBlank
    @Column(unique = true, nullable = false)
    private String rut;

    @NotBlank
    @Pattern(regexp = "[0-9Kk]", message = "DV debe ser número o K")
    @Column(nullable = false, length = 1)
    private String dv;

    @NotBlank
    @Column(nullable = false)
    private String name;

    @NotBlank
    @Column(nullable = false)
    private String lastName;

    @Column(name = "birth_date")
    private LocalDate birthDate;

    @NotBlank
    @Email
    @Column(unique = true, nullable = false)
    private String email;

    @NotBlank
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "modified_at", nullable = false)
    private LocalDateTime modifiedAt;

    // Método para obtener el RUT completo con DV
    public String getFullRut() {
        return rut + "-" + dv.toUpperCase();
    }

    /**
     * Valida el RUT utilizando la clase RutValidator
     * @return true si el RUT es válido, false en caso contrario
     */
    public boolean isValidRut() {
        return RutValidator.validarRut(this.rut, this.dv);
    }

    /**
     * Activa el usuario estableciendo isActive a true
     */
    public void activate() {
        this.isActive = true;
    }

    /**
     * Desactiva el usuario estableciendo isActive a false
     */
    public void deactivate() {
        this.isActive = false;
    }

}