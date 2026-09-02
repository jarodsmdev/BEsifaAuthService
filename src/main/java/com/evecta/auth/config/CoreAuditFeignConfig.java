package com.evecta.auth.config;

import feign.Request;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración de timeout para el Feign client del Core service.
 *
 * El intento inmediato de auditoría es síncrono en el hilo de la petición del
 * usuario, por lo que se usa un timeout corto para no bloquear al usuario si
 * Core está caído o lento. Los eventos que queden pendientes se reintentan por
 * el job programado (AuditEventRetryService).
 */
@Configuration
public class CoreAuditFeignConfig {

  @Bean
  public Request.Options coreServiceRequestOptions() {
    // conectTimeoutMs, readTimeoutMs
    return new Request.Options(3000, 5000);
  }
}
