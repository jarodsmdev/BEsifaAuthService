package com.evecta.auth.dto.token;

import java.time.LocalDateTime;

import com.evecta.auth.model.Token;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponseDTO {

    private Long idToken;
    private String token;
    private String tokenType;
    private boolean revoked;
    private boolean expired;
    private LocalDateTime expiresAt;
    private LocalDateTime createdAt;
    private LocalDateTime modifiedAt;
    private String userRut;
    private String userEmail;
    private String userName;
    private String userLastName;

    public static TokenResponseDTO fromEntity(Token token) {

        String tokenValue = token.getToken();

        // Esta linea enmascara el token dejando solo los primeros 5 caracteres visibles y el resto reemplazado por asteriscos
        String maskedToken = tokenValue != null && tokenValue.length() > 5
                ? tokenValue.substring(0, 5) + "***********"
                : tokenValue;

        return TokenResponseDTO.builder()
                .idToken(token.getIdToken())
                .token(maskedToken)
                .tokenType(token.getTokenType().name())
                .revoked(token.isRevoked())
                .expired(token.isExpired())
                .expiresAt(token.getExpiresAt())
                .createdAt(token.getCreatedAt())
                .modifiedAt(token.getModifiedAt())
                .userRut(token.getUser().getRut())
                .userEmail(token.getUser().getEmail())
                .userName(token.getUser().getName())
                .userLastName(token.getUser().getLastName())
                .build();
    }
}