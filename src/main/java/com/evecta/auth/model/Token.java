package com.evecta.auth.model;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.*;

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

    @Column(unique = true, length = 1000)
    public String token;

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
}
