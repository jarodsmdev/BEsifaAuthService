package com.evecta.auth.controller;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.evecta.auth.dto.token.TokenResponseDTO;
import com.evecta.auth.service.TokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth/api/v1/tokens")
@RequiredArgsConstructor
@Slf4j
public class TokenController {

    private final TokenService tokenService;

    @GetMapping
    public ResponseEntity<Page<TokenResponseDTO>> getAllTokens(
            @PageableDefault(size = 20, sort = "idToken", direction = Sort.Direction.DESC) Pageable pageable) {
        log.info("Recibida solicitud para listar tokens - página: {}, tamaño: {}",
                pageable.getPageNumber(), pageable.getPageSize());
        return ResponseEntity.ok(tokenService.findAllTokens(pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<TokenResponseDTO> getTokenById(@PathVariable Long id) {
        log.info("Recibida solicitud de búsqueda de token por ID: {}", id);
        return ResponseEntity.ok(tokenService.findTokenById(id));
    }

    @GetMapping("/user/{rut}")
    public ResponseEntity<List<TokenResponseDTO>> getTokensByUserRut(@PathVariable String rut) {
        log.info("Recibida solicitud de búsqueda de tokens por RUT: {}", rut);
        return ResponseEntity.ok(tokenService.findTokensByUserRut(rut));
    }

    @PatchMapping("/{id}/revoke")
    public ResponseEntity<TokenResponseDTO> revokeToken(@PathVariable Long id) {
        log.info("Recibida solicitud de revocación de token ID: {}", id);
        return ResponseEntity.ok(tokenService.revokeToken(id));
    }

    @PatchMapping("/{id}/expire")
    public ResponseEntity<TokenResponseDTO> expireToken(@PathVariable Long id) {
        log.info("Recibida solicitud de expiración de token ID: {}", id);
        return ResponseEntity.ok(tokenService.expireToken(id));
    }
}
