package com.evecta.auth.service;

import com.evecta.auth.dto.token.TokenResponseDTO;

import java.util.List;

public interface ITokenService {

    List<TokenResponseDTO> findAllTokens();

    TokenResponseDTO findTokenById(Long id);

    List<TokenResponseDTO> findTokensByUserRut(String rut);

    TokenResponseDTO revokeToken(Long id);

    TokenResponseDTO expireToken(Long id);
}
