package com.evecta.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * Genera el <b>token interno</b> ({@code X-Auth-Identity}) que el auth-service
 * adjunta a sus llamadas directas a core-sifa (p.ej. el POST de auditoría
 * {@code /core/api/v1/internal/audit}).
 * <p>
 * Como core-sifa ya no confía en cabeceras planas ({@code X-Auth-User} /
 * {@code X-Auth-Roles}), toda llamada downstream debe ir firmada con el secreto
 * interno ({@code INTERNAL_JWT_SECRET}), de corta duración (60s). El issuer y
 * audience internos coinciden con los que valida core-sifa.
 */
@Service
public class InternalTokenService {

  private static final long EXPIRATION_SECONDS = 60;

  @Value("${jwt.internal.secret}")
  private String jwtSecret;

  @Value("${jwt.internal.issuer}")
  private String issuer;

  @Value("${jwt.internal.audience}")
  private String audience;

  /**
   * Genera un token interno firmado con el secreto interno del sistema.
   *
   * @param subject identificador del emisor (p.ej. el email del usuario o el nombre del servicio)
   * @param roles   roles que core-sifa debe otorgar a la petición
   * @return JWT compacto con issuer/audience internos y expiración de 60s
   */
  public String generateToken(String subject, List<String> roles) {
    Instant now = Instant.now();
    Instant expiry = now.plusSeconds(EXPIRATION_SECONDS);

    return Jwts.builder()
        .subject(subject)
        .issuer(issuer)
        .audience().add(audience).and()
        .issuedAt(Date.from(now))
        .expiration(Date.from(expiry))
        .claim("roles", roles)
        .signWith(getSignInKey())
        .compact();
  }

  private Key getSignInKey() {
    byte[] keyBytes;
    try {
      keyBytes = Decoders.BASE64.decode(jwtSecret);
    } catch (IllegalArgumentException ex) {
      keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
    }
    return Keys.hmacShaKeyFor(keyBytes);
  }
}