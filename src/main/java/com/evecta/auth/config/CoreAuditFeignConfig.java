package com.evecta.auth.config;

import com.evecta.auth.service.InternalTokenService;
import feign.Request;
import feign.RequestInterceptor;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuración de timeout y autenticación para el Feign client del Core service.
 *
 * El intento inmediato de auditoría es síncrono en el hilo de la petición del
 * usuario, por lo que se usa un timeout corto para no bloquear al usuario si
 * Core está caído o lento. Los eventos que queden pendientes se reintentan por
 * el job programado (AuditEventRetryService).
 *
 * Como core-sifa exige un token interno firmado ({@code X-Auth-Identity}) en toda
 * llamada directa, se inyecta un interceptor que firma cada request con el token
 * de corta duración y rol {@code USER_ADMIN} (requerido por el endpoint de auditoría).
 */
@Configuration
public class CoreAuditFeignConfig {

  @Bean
  public Request.Options coreServiceRequestOptions() {
    // conectTimeoutMs, readTimeoutMs
    return new Request.Options(3000, 5000);
  }

  @Bean
  public RequestInterceptor coreAuditAuthInterceptor(InternalTokenService internalTokenService) {
    return requestTemplate ->
        requestTemplate.header(
            "X-Auth-Identity",
            internalTokenService.generateToken("auth-service", List.of("USER_ADMIN")));
  }
}