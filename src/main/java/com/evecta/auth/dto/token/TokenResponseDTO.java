package com.evecta.auth.dto.token;

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
    private String userRut;
    private String userEmail;
    private String userName;
    private String userLastName;

    public static TokenResponseDTO fromEntity(Token token) {
        return TokenResponseDTO.builder()
                .idToken(token.getIdToken())
                .token(token.getToken())
                .tokenType(token.getTokenType().name())
                .revoked(token.isRevoked())
                .expired(token.isExpired())
                .userRut(token.getUser().getRut())
                .userEmail(token.getUser().getEmail())
                .userName(token.getUser().getName())
                .userLastName(token.getUser().getLastName())
                .build();
    }
}
