package com.evecta.auth.repository;

import com.evecta.auth.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

public interface ITokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByToken(String token);

    List<Token> findAllByUser_RutAndExpiredFalseAndRevokedFalse(String rut);
}