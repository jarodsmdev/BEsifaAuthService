package com.evecta.auth.model;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.*;
import lombok.*;

/**
 * Entidad que representa un token de autenticación almacenado en base de datos.
 *
 * <p>Almacena tanto tokens de acceso (JWT) como refresh tokens (opacos).
 * Los refresh tokens se almacenan como hashes SHA-256 con salt para proteger
 * contra compromisos de la base de datos.
 *
 * <p>Campos de rotación (solo para refresh tokens):
 * <ul>
 *   <li>{@code familyId}: UUID que agrupa la cadena de rotación de tokens</li>
 *   <li>{@code replacedByTokenHash}: Hash del token que reemplazó a este</li>
 * </ul>
 *
 * <p>Si un refresh token con {@code replacedByTokenHash != null} se reutiliza,
 * significa que fue comprometido y se debe revocar toda la familia.
 */
@Setter @Getter @Builder
@NoArgsConstructor @AllArgsConstructor
@Entity(name = "tokens")
public class Token {
    public enum TokenType {
        BEARER,
        REFRESH
    }

    @Id
    @GeneratedValue(strategy =  GenerationType.IDENTITY)
    public Long idToken;

    /**
     * Token en texto plano.
     * Para BEARER: almacena el JWT completo (se valida por firma, no por lookup).
     * Para REFRESH: DEPRECATED - usar tokenHash/tokenSalt en su lugar.
     */
    @Column(length = 1000)
    public String token;

    /**
     * Hash SHA-256 del refresh token (solo para TokenType.REFRESH).
     * Se almacena en hexadecimal (64 caracteres).
     * Determinístico: permite búsqueda directa por findByTokenHash().
     */
    @Column(unique = true, length = 64)
    private String tokenHash;

    /**
     * Identificador único de la familia de rotación de refresh tokens.
     * Se genera una vez por sesión (login) y se mantiene en toda la cadena
     * de rotaciones. Permite revocar todos los tokens de una sesión.
     */
    @Column(length = 36)
    private String familyId;

    /**
     * Hash del refresh token que reemplazó a este token.
     * Cuando se rota un refresh token, el hash del nuevo token se guarda aquí.
     * Si un token con {@code replacedByTokenHash != null} se reutiliza,
     * indica que fue comprometido.
     */
    @Column(length = 64)
    private String replacedByTokenHash;

    @Enumerated(EnumType.STRING)
    public TokenType tokenType;

    public boolean revoked;

    public boolean expired;

    private LocalDateTime expiresAt;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime modifiedAt;

    @PrePersist
    private void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        if (modifiedAt == null) modifiedAt = now;
    }

    @PreUpdate
    private void preUpdate() {
        modifiedAt = LocalDateTime.now();
    }

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public UserEntity user;

    /**
     * Genera un nuevo familyId para una cadena de rotación de tokens.
     * Se llama al hacer login para iniciar una nueva familia.
     *
     * @return UUID como string
     */
    public static String generateFamilyId() {
        return UUID.randomUUID().toString();
    }
}
