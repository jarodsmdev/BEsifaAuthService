package com.evecta.auth.service;

import com.evecta.auth.client.CoreAuditClient;
import com.evecta.auth.dto.core.AuditLogRequestDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditoriaService {

  private final CoreAuditClient coreAuditClient;

  @Async
  public void registrarAccionAsincrona(String email, String accion, Map<String, Object> detalles) {
    try {
      AuditLogRequestDTO logRequest =
          AuditLogRequestDTO.builder()
              .emailUsuario(email)
              .accion(accion)
              .detalles(detalles)
              .build();

      coreAuditClient.registrarLog(logRequest);
    } catch (Exception e) {
      // Atrapamos el error para que NO afecte al usuario.
      // Si el Core está caído o la red privada falla, el usuario igual podrá iniciar sesión.
      log.error("Error silencioso al enviar log de auditoría al Core: {}", e.getMessage());
    }
  }
}
