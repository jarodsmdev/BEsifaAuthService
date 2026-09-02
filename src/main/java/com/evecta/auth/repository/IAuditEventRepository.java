package com.evecta.auth.repository;

import com.evecta.auth.model.AuditEvent;
import com.evecta.auth.model.EstadoAuditoria;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IAuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findByEstadoAndIntentosLessThan(EstadoAuditoria estado, int maxIntentos, Pageable pageable);

    long countByEstado(EstadoAuditoria estado);
}
