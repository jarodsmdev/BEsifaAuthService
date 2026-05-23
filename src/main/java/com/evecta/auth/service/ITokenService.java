package com.evecta.auth.service;

import com.evecta.auth.dto.token.TokenResponseDTO;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface ITokenService {

    Page<TokenResponseDTO> findAllTokens(Pageable pageable);

    TokenResponseDTO findTokenById(Long id);

    List<TokenResponseDTO> findTokensByUserRut(String rut);

    TokenResponseDTO revokeToken(Long id);

    TokenResponseDTO expireToken(Long id);
}
