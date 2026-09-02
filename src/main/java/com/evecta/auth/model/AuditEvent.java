package com.evecta.auth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_events")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditEvent {

    public static final int MIN_INTENTOS = 0;
    public static final int MAX_INTENTOS = 5;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email_usuario", nullable = false)
    private String emailUsuario;

    @Column(nullable = false)
    private String accion;

    @Column(name = "tabla_afectada")
    private String tablaAfectada;

    @Column(name = "id_registro_afectado")
    private String idRegistroAfectado;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String detallesJson;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private EstadoAuditoria estado = EstadoAuditoria.PENDING;

    @Column(nullable = false)
    @Builder.Default
    private int intentos = MIN_INTENTOS;

    @Column(name = "max_intentos", nullable = false)
    @Builder.Default
    private int maxIntentos = MAX_INTENTOS;

    @Column(name = "fecha_creacion", nullable = false, updatable = false)
    private LocalDateTime fechaCreacion;

    @Column(name = "fecha_ultimo_intento")
    private LocalDateTime fechaUltimoIntento;

    @Column(name = "ultimo_error", columnDefinition = "TEXT")
    private String ultimoError;

    @PrePersist
    protected void onCreate() {
        if (this.fechaCreacion == null) {
            this.fechaCreacion = LocalDateTime.now();
        }
    }
}
