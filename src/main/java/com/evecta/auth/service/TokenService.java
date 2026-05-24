package com.evecta.auth.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.evecta.auth.dto.token.TokenResponseDTO;
import com.evecta.auth.model.Token;
import com.evecta.auth.repository.ITokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService implements ITokenService {

    private final ITokenRepository tokenRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<TokenResponseDTO> findAllTokens(Pageable pageable) {
        log.info("Listando tokens - página: {}, tamaño: {}", pageable.getPageNumber(), pageable.getPageSize());
        return tokenRepository.findAllByOrderByIdTokenDesc(pageable)
                .map(TokenResponseDTO::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public TokenResponseDTO findTokenById(Long id) {
        log.info("Buscando token por ID: {}", id);
        Token token = tokenRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Token no encontrado con ID: " + id));
        return TokenResponseDTO.fromEntity(token);
    }

    @Override
    @Transactional(readOnly = true)
    public List<TokenResponseDTO> findTokensByUserRut(String rut) {
        log.info("Buscando tokens por RUT de usuario: {}", rut);
        return tokenRepository.findAllByUser_Rut(rut)
                .stream()
                .map(TokenResponseDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public TokenResponseDTO revokeToken(Long id) {
        log.info("Revocando token ID: {}", id);
        Token token = tokenRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Token no encontrado con ID: " + id));

        if (token.isExpired() || token.isRevoked()) {
            throw new IllegalStateException("El token ya ha sido invalidado (expirado o revocado)");
        }

        token.setRevoked(true);
        Token updatedToken = tokenRepository.save(token);
        log.info("Token revocado exitosamente: {}", id);
        return TokenResponseDTO.fromEntity(updatedToken);
    }

    @Override
    @Transactional
    public TokenResponseDTO expireToken(Long id) {
        log.info("Expiramdo token ID: {}", id);
        Token token = tokenRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Token no encontrado con ID: " + id));

        if (token.isExpired() || token.isRevoked()) {
            throw new IllegalStateException("El token ya ha sido invalidado (expirado o revocado)");
        }

        token.setExpired(true);
        Token updatedToken = tokenRepository.save(token);
        log.info("Token expirado exitosamente: {}", id);
        return TokenResponseDTO.fromEntity(updatedToken);
    }
}
