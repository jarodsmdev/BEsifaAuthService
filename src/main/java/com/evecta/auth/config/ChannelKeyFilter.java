package com.evecta.auth.config;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guardia del canal interno: exige que toda petición llegue con la cabecera
 * {@code X-Internal-Key} firmada con {@code INTERNAL_CHANNEL_KEY}.
 * <p>
 * A diferencia de la validación de token, este filtro cubre <b>todas</b> las
 * rutas, incluidas las públicas de {@code /auth/api/v1/**}, que es
 * justamente donde el gateway no inyecta identidad.
 * <p>
 * Excepciones:
 * <ul>
 *   <li>Tráfico de loopback: los healthchecks del contenedor viajan por
 *       {@code localhost} y no pasan por el gateway.</li>
 *   <li>{@code INTERNAL_CHANNEL_KEY} sin definir: guardia desactivada (se avisa
 *       en el arranque).</li>
 * </ul>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ChannelKeyFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ChannelKeyFilter.class);

    static final String CHANNEL_KEY_HEADER = "X-Internal-Key";

    private final String channelKey;

    public ChannelKeyFilter(@Value("${internal.channel.key:}") String channelKey) {
        this.channelKey = channelKey == null ? "" : channelKey.trim();
    }

    @PostConstruct
    void logStatus() {
        if (channelKey.isEmpty()) {
            log.warn("[!] INTERNAL_CHANNEL_KEY no definida: el canal interno NO está protegido.");
        } else {
            log.info("[+] Canal interno activo: se exige {}", CHANNEL_KEY_HEADER);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (channelKey.isEmpty() || isLoopback(request.getRemoteAddr())) {
            filterChain.doFilter(request, response);
            return;
        }

        String provided = request.getHeader(CHANNEL_KEY_HEADER);
        if (provided == null || !constantTimeEquals(channelKey, provided)) {
            log.warn("[-] Petición sin cabecera de canal válida desde {}: {} {}",
                    request.getRemoteAddr(), request.getMethod(), request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"Canal interno no válido\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private static boolean isLoopback(String remoteAddr) {
        return remoteAddr != null
                && (remoteAddr.equals("127.0.0.1")
                || remoteAddr.equals("0:0:0:0:0:0:0:1")
                || remoteAddr.equals("::1"));
    }

    /** Comparación en tiempo constante para no filtrar el secreto por timing. */
    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
