package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.evecta.auth.client.CoreAuditClient;
import com.evecta.auth.dto.core.AuditLogRequestDTO;

@ExtendWith(MockitoExtension.class)
class AuditoriaServiceTest {

    @Mock
    private CoreAuditClient coreAuditClient;

    @InjectMocks
    private AuditoriaService auditoriaService;

    @Captor
    private ArgumentCaptor<AuditLogRequestDTO> auditCaptor;

    @Test
    void registrarAccion_conTablaYId_enviaAClient() {
        Map<String, Object> detalles = Map.of("key", "value");

        auditoriaService.registrarAccionAsincrona(
                "user@example.com", "USUARIO_CREADO", "users", "12345", detalles);

        verify(coreAuditClient).registrarLog(auditCaptor.capture());
        AuditLogRequestDTO captured = auditCaptor.getValue();
        assertEquals("user@example.com", captured.getEmailUsuario());
        assertEquals("USUARIO_CREADO", captured.getAccion());
        assertEquals("users", captured.getTablaAfectada());
        assertEquals("12345", captured.getIdRegistroAfectado());
        assertEquals(detalles, captured.getDetalles());
    }

    @Test
    void registrarAccion_sinTabla_enviaAClient() {
        Map<String, Object> detalles = Map.of("Estado", "Exitoso");

        auditoriaService.registrarAccionAsincrona(
                "user@example.com", "LOGIN", detalles);

        verify(coreAuditClient).registrarLog(auditCaptor.capture());
        AuditLogRequestDTO captured = auditCaptor.getValue();
        assertNull(captured.getTablaAfectada());
        assertNull(captured.getIdRegistroAfectado());
    }

    @Test
    void registrarAccion_clientFalla_noPropagaExcepcion() {
        doThrow(new RuntimeException("Feign error"))
                .when(coreAuditClient).registrarLog(any(AuditLogRequestDTO.class));

        auditoriaService.registrarAccionAsincrona(
                "user@example.com", "LOGIN", Map.of("key", "value"));

        verify(coreAuditClient).registrarLog(any(AuditLogRequestDTO.class));
    }
}
