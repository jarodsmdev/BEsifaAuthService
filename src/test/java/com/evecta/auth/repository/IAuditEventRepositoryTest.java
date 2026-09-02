package com.evecta.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;

import com.evecta.auth.model.AuditEvent;
import com.evecta.auth.model.EstadoAuditoria;

@DataJpaTest
@DisplayName("IAuditEventRepository")
class IAuditEventRepositoryTest {

    @Autowired
    private IAuditEventRepository auditEventRepository;

    @BeforeEach
    void setUp() {
        auditEventRepository.deleteAll();
    }

    private AuditEvent evento(EstadoAuditoria estado, int intentos) {
        return AuditEvent.builder()
                .emailUsuario("user@example.com")
                .accion("LOGIN")
                .detallesJson("{\"Estado\":\"Exitoso\"}")
                .estado(estado)
                .intentos(intentos)
                .maxIntentos(5)
                .build();
    }

    @Test
    @DisplayName("findByEstadoAndIntentosLessThan retorna solo pendientes por debajo del máximo")
    void findByEstadoAndIntentosLessThan_pendientesElegibles() {
        auditEventRepository.save(evento(EstadoAuditoria.PENDING, 1));
        auditEventRepository.save(evento(EstadoAuditoria.PENDING, 5));
        auditEventRepository.save(evento(EstadoAuditoria.SENT, 1));

        List<AuditEvent> elegibles = auditEventRepository.findByEstadoAndIntentosLessThan(
                EstadoAuditoria.PENDING, 5, PageRequest.of(0, 10));

        assertThat(elegibles).hasSize(1);
        assertThat(elegibles.get(0).getAccion()).isEqualTo("LOGIN");
    }

    @Test
    @DisplayName("countByEstado cuenta correctamente por estado")
    void countByEstado_cuentaPorEstado() {
        auditEventRepository.save(evento(EstadoAuditoria.PENDING, 1));
        auditEventRepository.save(evento(EstadoAuditoria.FAILED, 5));
        auditEventRepository.save(evento(EstadoAuditoria.FAILED, 5));

        assertThat(auditEventRepository.countByEstado(EstadoAuditoria.PENDING)).isEqualTo(1);
        assertThat(auditEventRepository.countByEstado(EstadoAuditoria.FAILED)).isEqualTo(2);
    }
}
