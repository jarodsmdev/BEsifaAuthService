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

  // MÉTODO ORIGINAL (Para Login/Logout donde no hay tabla ni ID afectados)
  @Async
  public void registrarAccionAsincrona(String email, String accion, Map<String, Object> detalles) {
    // Delegamos la llamada al método principal enviando null en la tabla e id
    this.registrarAccionAsincrona(email, accion, null, null, detalles);
  }

  // 2. NUEVO MÉTODO PRINCIPAL (Para operaciones CRUD)
  @Async
  public void registrarAccionAsincrona(
      String email,
      String accion,
      String tablaAfectada,
      String idRegistroAfectado,
      Map<String, Object> detalles) {
    try {
      log.debug("[AUDITORIA] Iniciando envío asíncrono -> Usuario: {} | Acción: {}", email, accion);

      AuditLogRequestDTO logRequest =
          AuditLogRequestDTO.builder()
              .emailUsuario(email)
              .accion(accion)
              .tablaAfectada((tablaAfectada))
              .idRegistroAfectado(idRegistroAfectado)
              .detalles(detalles)
              .build();

      log.debug("[AUDITORIA] Payload construido: {}", logRequest);

      coreAuditClient.registrarLog(logRequest);

      log.debug("[AUDITORIA] Log enviado exitosamente al Core Service.");

    } catch (IllegalArgumentException e) {
      log.error("[AUDITORIA-ERROR] Fallo de validación de URI o argumentos.");
      log.error("Mensaje: {}", e.getMessage());
      log.error("Stacktrace:", e);
    } catch (Exception e) {
      // Atrapamos el error para que NO afecte al usuario.
      log.error("[AUDITORIA-ERROR] Error silencioso general al comunicarse con el Core.");
      log.error("Clase del error: {}", e.getClass().getName());
      log.error("Mensaje exacto: {}", e.getMessage());
      if (e.getCause() != null) {
        log.error("Causa raíz (Cause): {}", e.getCause().toString());
      }
      // Imprime el stacktrace completo para ver exactamente en qué clase de Feign falló
      log.error("Stacktrace completo: ", e);
    }
  }
}
