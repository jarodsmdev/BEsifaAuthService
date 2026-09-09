package com.evecta.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.evecta.auth.model.UserEntity;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

  @Value("${app.jwt.secret}")
  private String jwtSecret;

  @Value("${app.jwt.expiration-seconds}")
  private long expirationSeconds;

  // Claims estándar para validación en servicios downstream
  @Value("${app.jwt.issuer}")
  private String issuer;

  @Value("${app.jwt.audience}")
  private String audience;

  public AuthTokenData generateToken(UserEntity user, List<String> roles, List<String> permisos) {
    Instant now = Instant.now();
    Instant expiry = now.plusSeconds(expirationSeconds);

    // Claims estándar para validación en servicios downstream:
    // - issuer: identifica el servicio emisor del token
    // - audience: identifica los servicios destinatarios autorizados
    // Nota: En JJWT 0.12.x, .audience() retorna BuilderAudience que requiere .add() y .and()
    String token =
        Jwts.builder()
            .subject(user.getEmail())
            .issuer(issuer)
            .audience().add(audience).and()
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .claim("roles", roles)
            .claim("permisos", permisos)
            .signWith(getSignInKey())
            .compact();

    return new AuthTokenData(
        token, user.getEmail(), now.getEpochSecond(), expiry.getEpochSecond(), roles, permisos);
  }

  public boolean isTokenValid(String token) {
    try {
      extractAllClaims(token);
      return true;
    } catch (Exception e) {
      return false;
    }
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

  public String extractUsername(String token) {
    return extractAllClaims(token).getSubject();
  }

  @SuppressWarnings("unchecked")
  public List<String> extractRoles(String token) {
    Claims claims = extractAllClaims(token);

    return claims.get("roles", List.class);
  }

  private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith((javax.crypto.SecretKey) getSignInKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  public record AuthTokenData(
      String token, String sub, Long iat, Long exp, List<String> roles, List<String> permisos) {}
}
