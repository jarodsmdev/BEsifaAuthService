package com.evecta.auth.service;

import com.evecta.auth.client.CoreAuditClient;
import com.evecta.auth.dto.core.AuditLogRequestDTO;
import com.evecta.auth.model.AuditEvent;
import com.evecta.auth.model.EstadoAuditoria;
import com.evecta.auth.repository.IAuditEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditoriaService {

  private final IAuditEventRepository auditEventRepository;
  private final CoreAuditClient coreAuditClient;
  private final ObjectMapper objectMapper;

  // Método para Login/Logout donde no hay tabla ni ID afectados
  @Transactional
  public void registrarAccion(String email, String accion, Map<String, Object> detalles) {
    this.registrarAccion(email, accion, null, null, detalles);
  }

  // Método principal para operaciones CRUD
  @Transactional
  public void registrarAccion(
      String email,
      String accion,
      String tablaAfectada,
      String idRegistroAfectado,
      Map<String, Object> detalles) {

    log.debug("[AUDITORIA] Registrando acción -> Usuario: {} | Acción: {}", email, accion);

    // 1. Serializar detalles a JSON para persistencia local
    String detallesJson;
    try {
      detallesJson = objectMapper.writeValueAsString(detalles);
    } catch (JsonProcessingException e) {
      log.error("[AUDITORIA-ERROR] No se pudo serializar los detalles de la acción '{}'", accion, e);
      return;
    }

    // 2. Persistir el evento localmente (outbox) en la misma transacción
    AuditEvent evento = AuditEvent.builder()
        .emailUsuario(email)
        .accion(accion)
        .tablaAfectada(tablaAfectada)
        .idRegistroAfectado(idRegistroAfectado)
        .detallesJson(detallesJson)
        .estado(EstadoAuditoria.PENDING)
        .intentos(0)
        .build();

    AuditEvent guardado = auditEventRepository.save(evento);

    // 3. Intento inmediato de envío a Core (síncrono, con timeout corto).
    //    Si falla, el evento permanece PENDING y lo reintenta el job programado.
    intentarEnvio(guardado);
  }

  /**
   * Intenta enviar un evento a Core. Actualiza el estado según el resultado.
   * Si el envío falla, el evento queda pendiente para su reintento posterior.
   */
  @Transactional
  public void intentarEnvio(AuditEvent evento) {
    if (evento.getEstado() == EstadoAuditoria.SENT) {
      return;
    }

    AuditLogRequestDTO request = AuditLogRequestDTO.builder()
        .emailUsuario(evento.getEmailUsuario())
        .accion(evento.getAccion())
        .tablaAfectada(evento.getTablaAfectada())
        .idRegistroAfectado(evento.getIdRegistroAfectado())
        .detalles(deserializarDetalles(evento.getDetallesJson()))
        .build();

    try {
      coreAuditClient.registrarLog(request);
      evento.setEstado(EstadoAuditoria.SENT);
      evento.setIntentos(evento.getIntentos() + 1);
      evento.setFechaUltimoIntento(LocalDateTime.now());
      evento.setUltimoError(null);
      auditEventRepository.save(evento);
      log.debug("[AUDITORIA] Log enviado al Core exitosamente | Usuario: {} | Acción: {}", request.getEmailUsuario(), request.getAccion());
    } catch (Exception e) {
      evento.setIntentos(evento.getIntentos() + 1);
      evento.setFechaUltimoIntento(LocalDateTime.now());
      evento.setUltimoError(resumirError(e));

      if (evento.getIntentos() >= evento.getMaxIntentos()) {
        evento.setEstado(EstadoAuditoria.FAILED);
        log.error("[AUDITORIA-ALERTA] Evento alcanzó el máximo de intentos ({}) y fue marcado como FALLIDO. "
                + "Usuario: {} | Acción: {} | Error: {}",
            evento.getMaxIntentos(), request.getEmailUsuario(), request.getAccion(), resumirError(e));
      } else {
        log.warn("[AUDITORIA] Envío fallido (intento {}/{}) -> Usuario: {} | Acción: {} | Error: {}",
            evento.getIntentos(), evento.getMaxIntentos(), request.getEmailUsuario(), request.getAccion(), resumirError(e));
      }

      auditEventRepository.save(evento);
    }
  }

  private Map<String, Object> deserializarDetalles(String detallesJson) {
    try {
      return objectMapper.readValue(detallesJson, objectMapper.getTypeFactory()
          .constructMapType(Map.class, String.class, Object.class));
    } catch (JsonProcessingException e) {
      log.warn("[AUDITORIA] No se pudo deserializar detalles del evento, se envía vacío");
      return Map.of();
    }
  }

  private String resumirError(Exception e) {
    String message = e.getMessage();
    return (message == null || message.isBlank()) ? e.getClass().getSimpleName() : message;
  }
}
