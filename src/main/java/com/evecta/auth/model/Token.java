package com.evecta.auth.model;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

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

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime modifiedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public UserEntity user;
}
