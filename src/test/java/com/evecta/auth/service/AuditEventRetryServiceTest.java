package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;

import com.evecta.auth.model.AuditEvent;
import com.evecta.auth.model.EstadoAuditoria;
import com.evecta.auth.repository.IAuditEventRepository;

@ExtendWith(MockitoExtension.class)
class AuditEventRetryServiceTest {

    @Mock
    private IAuditEventRepository auditEventRepository;

    @Mock
    private AuditoriaService auditoriaService;

    @InjectMocks
    private AuditEventRetryService retryService;

    private AuditEvent eventoPendiente() {
        return AuditEvent.builder()
                .id(1L)
                .emailUsuario("user@example.com")
                .accion("LOGIN")
                .detallesJson("{}")
                .estado(EstadoAuditoria.PENDING)
                .intentos(1)
                .maxIntentos(5)
                .build();
    }

    @Test
    void reenviarPendientes_sinPendientes_noHaceNada() {
        when(auditEventRepository.findByEstadoAndIntentosLessThan(
                eq(EstadoAuditoria.PENDING), eq(5), any(PageRequest.class)))
                .thenReturn(List.of());

        retryService.reenviarPendientes();

        verify(auditoriaService, never()).intentarEnvio(any());
    }

    @Test
    void reenviarPendientes_conPendientes_reintentaCadaUno() {
        List<AuditEvent> pendientes = List.of(eventoPendiente(), eventoPendiente());
        when(auditEventRepository.findByEstadoAndIntentosLessThan(
                eq(EstadoAuditoria.PENDING), eq(5), any(PageRequest.class)))
                .thenReturn(pendientes);

        retryService.reenviarPendientes();

        verify(auditoriaService, times(2)).intentarEnvio(any(AuditEvent.class));
    }

    @Test
    void contarFallidos_devuelveCantidad() {
        when(auditEventRepository.countByEstado(EstadoAuditoria.FAILED)).thenReturn(3L);

        long resultado = retryService.contarFallidos();

        verify(auditEventRepository).countByEstado(EstadoAuditoria.FAILED);
        assertEquals(3L, resultado);
    }
}
