package com.evecta.auth.service;

import com.evecta.auth.model.AuditEvent;
import com.evecta.auth.model.EstadoAuditoria;
import com.evecta.auth.repository.IAuditEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Job programado que reintenta el envío de eventos de auditoría pendientes al
 * Core service. Evita la pérdida de eventos si Core estuvo caído o lento en el
 * intento inmediato.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditEventRetryService {

  private static final int BATCH_SIZE = 50;

  private final IAuditEventRepository auditEventRepository;
  private final AuditoriaService auditoriaService;

  @Scheduled(fixedDelayString = "${audit.retry.interval-ms:30000}")
  @Transactional
  public void reenviarPendientes() {
    List<AuditEvent> pendientes =
        auditEventRepository.findByEstadoAndIntentosLessThan(
            EstadoAuditoria.PENDING, AuditEvent.MAX_INTENTOS, PageRequest.of(0, BATCH_SIZE));

    if (pendientes.isEmpty()) {
      return;
    }

    log.info("[AUDITORIA-RETRY] Procesando {} eventos pendientes de auditoría", pendientes.size());
    pendientes.forEach(auditoriaService::intentarEnvio);
  }

  /**
   * Expone métricas de eventos fallidos para alertas/monitoreo.
   */
  public long contarFallidos() {
    return auditEventRepository.countByEstado(EstadoAuditoria.FAILED);
  }
}
