package com.evecta.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

  @Value("${gateway.public.url}")
  private String gatewayUrl;

  @Bean
  public OpenAPI coreOpenAPI() {
    final String securitySchemeName = "bearerAuth";

    // Configura la URL base a través de la cual Swagger ejecutará los "Try it out"
    Server gatewayServer =
        new Server()
            .url(gatewayUrl) // URL pública del API Gateway
            .description("API Gateway Perimetral (Entorno de Desarrollo)");

    return new OpenAPI()
        .info(
            new Info()
                .title("Módulo de Autenticación y Seguridad - SIFA")
                .version("1.0.0")
                .description(
                    "Servicio encargado de la gestión de identidades, control de acceso basado en roles (RBAC) y emisión de Tokens JWT."))
        .servers(List.of(gatewayServer))
        .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
        .components(
            new Components()
                .addSecuritySchemes(
                    securitySchemeName,
                    new SecurityScheme()
                        .name(securitySchemeName)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description(
                            "Ingresa el Token JWT obtenido en el login para interactuar con las APIs protegidas.")));
  }
}
