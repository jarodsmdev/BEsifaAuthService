package com.evecta.auth.model;

import jakarta.persistence.*;
import lombok.*;

@Setter @Getter @Builder
@NoArgsConstructor @AllArgsConstructor
@Entity(name = "tokens")
public class Token {
    public enum TokenType {
        BEARER
    }

    @Id
    @GeneratedValue(strategy =  GenerationType.IDENTITY)
    public Long idToken;

    @Column(unique = true)
    public String token;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    public TokenType tokenType = TokenType.BEARER;

    public boolean revoked;

    public boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public UserEntity user;
}
