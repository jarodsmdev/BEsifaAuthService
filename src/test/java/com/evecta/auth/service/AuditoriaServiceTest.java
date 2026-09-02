package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.evecta.auth.client.CoreAuditClient;
import com.evecta.auth.dto.core.AuditLogRequestDTO;
import com.evecta.auth.model.AuditEvent;
import com.evecta.auth.model.EstadoAuditoria;
import com.evecta.auth.repository.IAuditEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
class AuditoriaServiceTest {

    @Mock
    private IAuditEventRepository auditEventRepository;

    @Mock
    private CoreAuditClient coreAuditClient;

    @InjectMocks
    private AuditoriaService auditoriaService;

    @Captor
    private ArgumentCaptor<AuditEvent> eventCaptor;

    @Captor
    private ArgumentCaptor<AuditLogRequestDTO> auditCaptor;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        auditoriaService = new AuditoriaService(auditEventRepository, coreAuditClient, objectMapper);
    }

    private AuditEvent stubSave() {
        AuditEvent saved = AuditEvent.builder()
                .id(1L)
                .emailUsuario("user@example.com")
                .accion("USUARIO_CREADO")
                .tablaAfectada("users")
                .idRegistroAfectado("12345")
                .detallesJson("{\"key\":\"value\"}")
                .estado(EstadoAuditoria.PENDING)
                .build();
        when(auditEventRepository.save(any(AuditEvent.class))).thenReturn(saved);
        return saved;
    }

    @Test
    void registrarAccion_conTablaYId_persisteYEnviaAClient() throws Exception {
        stubSave();
        Map<String, Object> detalles = Map.of("key", "value");

        auditoriaService.registrarAccion(
                "user@example.com", "USUARIO_CREADO", "users", "12345", detalles);

        verify(auditEventRepository, atLeastOnce()).save(eventCaptor.capture());
        AuditEvent persisted = eventCaptor.getAllValues().get(0);
        assertEquals("user@example.com", persisted.getEmailUsuario());
        assertEquals("USUARIO_CREADO", persisted.getAccion());
        assertEquals("users", persisted.getTablaAfectada());
        assertEquals("12345", persisted.getIdRegistroAfectado());
        assertEquals(EstadoAuditoria.PENDING, persisted.getEstado());

        verify(coreAuditClient).registrarLog(auditCaptor.capture());
        AuditLogRequestDTO captured = auditCaptor.getValue();
        assertEquals("user@example.com", captured.getEmailUsuario());
        assertEquals("USUARIO_CREADO", captured.getAccion());
        assertEquals("users", captured.getTablaAfectada());
        assertEquals("12345", captured.getIdRegistroAfectado());
        assertEquals(detalles, captured.getDetalles());
    }

    @Test
    void registrarAccion_sinTabla_persisteYEnviaAClient() throws Exception {
        AuditEvent saved = AuditEvent.builder()
                .id(1L)
                .emailUsuario("user@example.com")
                .accion("LOGIN")
                .detallesJson("{\"Estado\":\"Exitoso\"}")
                .estado(EstadoAuditoria.PENDING)
                .build();
        when(auditEventRepository.save(any(AuditEvent.class))).thenReturn(saved);

        auditoriaService.registrarAccion(
                "user@example.com", "LOGIN", Map.of("Estado", "Exitoso"));

        verify(coreAuditClient).registrarLog(auditCaptor.capture());
        AuditLogRequestDTO captured = auditCaptor.getValue();
        assertNull(captured.getTablaAfectada());
        assertNull(captured.getIdRegistroAfectado());
        assertEquals(Map.of("Estado", "Exitoso"), captured.getDetalles());
    }

    @Test
    void registrarAccion_clientFalla_noPropagaYQuedaPendiente() throws Exception {
        AuditEvent saved = AuditEvent.builder()
                .id(1L)
                .emailUsuario("user@example.com")
                .accion("LOGIN")
                .detallesJson("{\"Estado\":\"Exitoso\"}")
                .estado(EstadoAuditoria.PENDING)
                .intentos(0)
                .maxIntentos(5)
                .build();
        when(auditEventRepository.save(any(AuditEvent.class))).thenReturn(saved);
        doThrow(new RuntimeException("Feign error"))
                .when(coreAuditClient).registrarLog(any(AuditLogRequestDTO.class));

        auditoriaService.registrarAccion(
                "user@example.com", "LOGIN", Map.of("Estado", "Exitoso"));

        verify(coreAuditClient).registrarLog(any(AuditLogRequestDTO.class));
        verify(auditEventRepository, times(2)).save(any(AuditEvent.class));
        assertEquals(EstadoAuditoria.PENDING, saved.getEstado());
        assertEquals(1, saved.getIntentos());
    }

    @Test
    void intentarEnvio_cuandoExcedeMaxIntentos_marcaFallido() throws Exception {
        AuditEvent evento = AuditEvent.builder()
                .id(1L)
                .emailUsuario("user@example.com")
                .accion("LOGIN")
                .detallesJson("{\"Estado\":\"Exitoso\"}")
                .estado(EstadoAuditoria.PENDING)
                .intentos(5)
                .maxIntentos(5)
                .build();
        doThrow(new RuntimeException("Feign error"))
                .when(coreAuditClient).registrarLog(any(AuditLogRequestDTO.class));

        auditoriaService.intentarEnvio(evento);

        assertEquals(EstadoAuditoria.FAILED, evento.getEstado());
        assertEquals(6, evento.getIntentos());
    }

    @Test
    void intentarEnvio_cuandoExito_marcaEnviado() throws Exception {
        AuditEvent evento = AuditEvent.builder()
                .id(1L)
                .emailUsuario("user@example.com")
                .accion("LOGIN")
                .detallesJson("{\"Estado\":\"Exitoso\"}")
                .estado(EstadoAuditoria.PENDING)
                .intentos(0)
                .build();

        auditoriaService.intentarEnvio(evento);

        assertEquals(EstadoAuditoria.SENT, evento.getEstado());
        assertEquals(1, evento.getIntentos());
        assertNull(evento.getUltimoError());
    }
}
