package com.evecta.auth.controller;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.auth.ChangePasswordRequestDTO;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import com.evecta.auth.dto.auth.MobileAuthResponseDTO;
import com.evecta.auth.dto.auth.PasswordRecoveryRequestDTO;
import com.evecta.auth.dto.auth.PasswordResetRequestDTO;
import com.evecta.auth.dto.auth.SessionStatusDTO;
import com.evecta.auth.dto.token.refresh.RefreshTokenRequestDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.AuthService;
import com.evecta.auth.util.CookieUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Controller de autenticación.
 * 
 * Endpoints perimetrales para autenticación y manejo de sesiones JWT.
 * 
 * Seguridad de tokens:
 * - Los tokens se almacenan como cookies HttpOnly, no accesibles desde JavaScript.
 * - Se usa SameSite=Strict para mitigar CSRF.
 * - El frontend solo recibe datos del usuario, nunca los tokens.
 * 
 * @see CookieUtil para el manejo de cookies
 */
@RestController
@RequestMapping("/auth/api/v1")
@Tag(
    name = "Autenticación",
    description = "Endpoints perimetrales para autenticación y manejo de sesiones JWT")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final ITokenRepository tokenRepository;

    /**
     * Inicia sesión de un usuario.
     * 
     * Según el origen del cliente:
     * - Web (navegador): establece cookies HttpOnly con los tokens de acceso y
     *   refresco. El body solo contiene la información del usuario.
     * - Mobile (app nativa): no puede usar cookies, por lo que recibe los
     *   tokens y claims (sub/iat/exp) directamente en el body JSON.
     * 
     * @param loginRequest Credenciales del usuario (email, password)
     * @param clientOrigin Origen del cliente ("web" o "mobile")
     * @param response Respuesta HTTP donde se establecen las cookies (solo web)
     * @return Información del usuario autenticado (web) o tokens + usuario (mobile)
     */
    @Operation(
            summary = "Iniciar sesión",
            description = "Autentica un usuario. En web establece cookies HttpOnly; en app móvil retorna los tokens en el body")
    @ApiResponse(
            responseCode = "200",
            description = "Login exitoso",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(oneOf = {AuthResponseDTO.class, MobileAuthResponseDTO.class})
            )
    )
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequestDTO loginRequest,
            @RequestHeader("X-Client-Origin") String clientOrigin,
            HttpServletResponse response) {

        log.info("Login request: {} from origin: {}", loginRequest.getEmail(), clientOrigin);

        AuthService.LoginResult result = authService.login(loginRequest, clientOrigin);

        // Clientes móviles (app nativa) no pueden usar cookies HttpOnly:
        // se retornan los tokens en el body directamente.
        if (isMobileClient(clientOrigin)) {
            MobileAuthResponseDTO mobileResponse = buildMobileResponse(
                    result.accessToken(), result.refreshToken(), result.sub(), result.iat(), result.exp(),
                    result.userResponse().getRoles());

            log.info("Login exitoso para usuario móvil: {}", result.userResponse().getEmail());
            return ResponseEntity.ok(mobileResponse);
        }

        // Clientes web: los tokens viajan en cookies HttpOnly
        CookieUtil.setAccessTokenCookie(response, result.accessToken());
        CookieUtil.setRefreshTokenCookie(response, result.refreshToken());

        log.info("Login exitoso para usuario: {}", result.userResponse().getEmail());
        return ResponseEntity.ok(result.userResponse());
    }

    /**
     * Cierra la sesión del usuario.
     * 
     * Obtiene el token desde la cookie access_token (o el header Authorization
     * como fallback para apps móviles), lo revoca en la base de datos y
     * limpia las cookies HttpOnly de la respuesta.
     * 
     * @param request Petición HTTP (para leer la cookie)
     * @param response Respuesta HTTP (para limpiar las cookies)
     * @param authHeader Header Authorization opcional (fallback para apps móviles)
     * @return Mensaje de confirmación
     */
    @Operation(
            summary = "Cerrar sesión",
            description = "Revoca el token actual y limpia las cookies HttpOnly",
            security = @SecurityRequirement(name = "bearerAuth"))
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response,
            @Parameter(
                    description = "JWT Bearer Token (opcional, fallback para apps móviles)",
                    required = false,
                    example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
            String authHeader) {

        // Obtener token desde cookie (preferente) o header (fallback)
        String token = CookieUtil.getAccessToken(request);
        boolean fromCookie = token != null;

        if (token == null && authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (token == null) {
            log.info("Logout fallido: no se encontró token en cookie ni header");
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "No se encontró token de sesión"));
        }

        log.info("Logout request (origen token: {})", fromCookie ? "cookie" : "header");

        try {
            authService.logout(token);
        } catch (IllegalArgumentException | IllegalStateException e) {
            log.warn("Logout con token inválido: {}", e.getMessage());
            // No fallamos el logout, simplemente limpiamos las cookies
        }

        // Limpiar cookies HttpOnly de la respuesta
        CookieUtil.clearAccessTokenCookie(response);
        CookieUtil.clearRefreshTokenCookie(response);

        log.info("Logout exitoso");
        return ResponseEntity.ok(
                Map.of("message", "Logout successful"));
    }

    /**
     * Verifica el estado de la sesión.
     * 
     * Este endpoint lee el access token de la cookie y valida si la sesión
     * es válida. Se usa al cargar la aplicación para restaurar la sesión
     * sin necesidad de que el frontend tenga acceso al token.
     * 
     * @param request Petición HTTP (para leer la cookie access_token)
     * @return SessionStatusDTO con el estado de la sesión
     */
    @Operation(
            summary = "Verificar estado de sesión",
            description = "Valida la sesión actual leyendo el token de la cookie httpOnly. Usado por el frontend para restaurar sesiones.")
    @GetMapping("/status")
    public ResponseEntity<SessionStatusDTO> sessionStatus(HttpServletRequest request) {

        String token = CookieUtil.getAccessToken(request);

        if (token == null) {
            log.info("Status: no hay cookie de sesión");
            return ResponseEntity.ok(
                    SessionStatusDTO.builder()
                            .valid(false)
                            .error("No hay sesión activa")
                            .build());
        }

        log.info("Status: validando sesión");
        SessionStatusDTO status = authService.validateSession(token);

        return ResponseEntity.ok(status);
    }

    /**
     * Valida si un token es válido.
     * 
     * Endpoint interno usado por el API Gateway para validar tokens.
     * Acepta el token desde el header Authorization (usado por el gateway)
     * o desde la cookie access_token (para validación directa).
     * 
     * @param request Petición HTTP (para leer la cookie)
     * @param authHeader Header Authorization (usado por el gateway)
     * @return Estado de validación del token
     */
    @Operation(
            summary = "Validar token",
            description = "Valida si el token JWT es válido, no expirado y no revocado",
            security = @SecurityRequirement(name = "bearerAuth"))
    @GetMapping("/validate")
    public ResponseEntity<?> validate(
            HttpServletRequest request,
            @Parameter(
                    description = "JWT Bearer Token",
                    required = false,
                    example = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false)
            String authHeader) {

        // Obtener token desde header (preferente, usado por el gateway) o cookie
        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        } else {
            token = CookieUtil.getAccessToken(request);
        }

        if (token == null) {
            log.info("Validación fallida: no se encontró token");
            return ResponseEntity.badRequest().body(
                    Map.of(
                            "valid", false,
                            "error", "Token no proporcionado"));
        }

        log.info("Validación de token solicitada");

        var storedToken = tokenRepository.findByToken(token).orElse(null);

        if (storedToken == null) {
            log.info("Token no encontrado en base de datos");
            return ResponseEntity.ok(
                    Map.of(
                            "valid", false,
                            "error", "Token no encontrado"));
        }

        if (storedToken.isExpired()) {
            log.info("Token expirado: {}", storedToken.getUser().getEmail());
            return ResponseEntity.ok(
                    Map.of(
                            "valid", false,
                            "error", "Token expirado",
                            "expired", true));
        }

        if (storedToken.isRevoked()) {
            log.info("Token revocado: {}", storedToken.getUser().getEmail());
            return ResponseEntity.ok(
                    Map.of(
                            "valid", false,
                            "error", "Token revocado",
                            "revoked", true));
        }

        log.info("Token válido para usuario: {}", storedToken.getUser().getEmail());
        return ResponseEntity.ok(
                Map.of(
                        "valid", true,
                        "message", "Token válido",
                        "user", storedToken.getUser().getEmail(),
                        "roles", resolveRoles(storedToken.getUser())));
    }

    /**
     * Renueva los tokens de acceso.
     * 
     * Según el origen del cliente:
     * - Web: lee el refresh token de la cookie refresh_token, rota los tokens y
     *   los establece como nuevas cookies (body solo con datos del usuario).
     * - Mobile: envía el refresh token en el body (las cookies no aplican), por
     *   lo que se retornan los nuevos tokens en el body JSON.
     * 
     * @param request Petición HTTP (para leer la cookie refresh_token)
     * @param response Respuesta HTTP (para establecer nuevas cookies, solo web)
     * @param requestBody Cuerpo opcional con refreshToken (fallback para apps móviles)
     * @return Información del usuario renovada (web) o tokens renovados (mobile)
     */
    @Operation(
            summary = "Renovar access token",
            description = "Genera un nuevo access token usando el refresh token de la cookie httpOnly (web) o del body (app móvil)")
    @ApiResponse(
            responseCode = "200",
            description = "Token renovado correctamente",
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(oneOf = {AuthResponseDTO.class, MobileAuthResponseDTO.class})
            )
    )
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestBody(required = false) RefreshTokenRequestDTO requestBody) {

        // Obtener refresh token desde cookie (preferente, clientes web) o request body (apps móviles)
        String refreshToken = CookieUtil.getRefreshToken(request);
        boolean fromCookie = refreshToken != null;

        if (refreshToken == null && requestBody != null) {
            refreshToken = requestBody.refreshToken();
        }

        if (refreshToken == null) {
            log.info("Refresh fallido: no se encontró refresh token en cookie ni body");
            return ResponseEntity.badRequest()
                    .body(buildErrorResponse("No se encontró refresh token"));
        }

        log.info("Refresh token solicitado (origen token: {})", fromCookie ? "cookie" : "body");
        AuthService.RefreshResult result = authService.refresh(refreshToken);

        // Cliente móvil: retornar los tokens rotados en el body (no usa cookies)
        if (!fromCookie) {
            MobileAuthResponseDTO mobileResponse = buildMobileResponse(
                    result.accessToken(), result.refreshToken(), result.sub(), result.iat(), result.exp(),
                    result.userResponse().getRoles());

            log.info("Refresh token exitoso para usuario móvil: {}", result.userResponse().getEmail());
            return ResponseEntity.ok(mobileResponse);
        }

        // Cliente web: establecer nuevos tokens como cookies HttpOnly
        CookieUtil.setAccessTokenCookie(response, result.accessToken());
        CookieUtil.setRefreshTokenCookie(response, result.refreshToken());

        log.info("Refresh token exitoso para usuario: {}", result.userResponse().getEmail());
        return ResponseEntity.ok(result.userResponse());
    }

    /**
     * Construye una respuesta de error con el mensaje dado.
     * 
     * @param message Mensaje de error
     * @return AuthResponseDTO vacío (el error se maneja con código HTTP)
     */
    private AuthResponseDTO buildErrorResponse(String message) {
        return AuthResponseDTO.builder()
                .authType("error")
                .roles(List.of())
                .build();
    }

    /**
     * Determina si el cliente es una app móvil nativa.
     * 
     * Las apps móviles no pueden usar cookies HttpOnly, por lo que reciben
     * los tokens directamente en el body JSON.
     * 
     * @param clientOrigin Valor del header X-Client-Origin
     * @return true si el cliente es móvil/app
     */
    private boolean isMobileClient(String clientOrigin) {
        return "mobile".equalsIgnoreCase(clientOrigin) || "app".equalsIgnoreCase(clientOrigin);
    }

    /**
     * Construye la respuesta de autenticación para clientes móviles.
     * 
     * Incluye los tokens y sus claims (sub/iat/exp) en el body JSON, ya que
     * una app nativa no puede leer las cookies HttpOnly. El formato replica
     * la respuesta original del backend para compatibilidad con el SDK móvil.
     * 
     * @param accessToken Token JWT de acceso
     * @param refreshToken Refresh token opaco
     * @param sub Asunto del token (email del usuario)
     * @param iat Timestamp de emisión (epoch seconds)
     * @param exp Timestamp de expiración (epoch seconds)
     * @param roles Roles del usuario
     * @return MobileAuthResponseDTO con tokens y claims
     */
    private MobileAuthResponseDTO buildMobileResponse(
            String accessToken,
            String refreshToken,
            String sub,
            Long iat,
            Long exp,
            List<String> roles) {

        return MobileAuthResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .sub(sub)
                .iat(iat)
                .exp(exp)
                .roles(roles)
                .build();
    }

    // SOLICITAR RECUPERACIÓN DE CONTRASEÑA
    @Operation(
            summary = "Solicitar recuperación de contraseña",
            description = "Genera y envía un código de 6 dígitos al correo del usuario")
    @ApiResponse(responseCode = "200", description = "Código enviado con éxito")
    @PostMapping("/recovery/request")
    public ResponseEntity<?> requestRecovery(
            @Valid @RequestBody PasswordRecoveryRequestDTO request) {
        
        log.info("Solicitud de recuperación de contraseña para: {}", request.getEmail());
        authService.initiatePasswordRecovery(request.getEmail());
        return ResponseEntity.ok(Map.of("message", "Código de recuperación enviado con éxito."));
    }

    // RESTABLECER CONTRASEÑA
    @Operation(
            summary = "Restablecer contraseña",
            description = "Valida el código de 6 dígitos e ingresa la nueva contraseña del usuario")
    @ApiResponse(responseCode = "200", description = "Contraseña restablecida con éxito")
    @PostMapping("/recovery/reset")
    public ResponseEntity<?> resetPassword(
            @Valid @RequestBody PasswordResetRequestDTO request) {
        
        log.info("Restablecimiento de contraseña solicitado para: {}", request.getEmail());
        authService.resetPassword(request);
        return ResponseEntity.ok(Map.of("message", "Contraseña restablecida con éxito."));
    }

    // CAMBIAR CONTRASEÑA (autenticado)
    @Operation(
            summary = "Cambiar contraseña",
            description = "Permite al usuario autenticado cambiar su contraseña proporcionando la actual y una nueva. Revoca todos los tokens existentes.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponse(responseCode = "200", description = "Contraseña cambiada con éxito")
    @PostMapping("/change-password")
    @PreAuthorize("hasAnyAuthority('USER_APP', 'USER_JPL', 'USER_SUPERVISOR', 'USER_ADMIN')")
    public ResponseEntity<?> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequestDTO request) {

        String email = authentication.getName();
        log.info("Cambio de contraseña para usuario: {}", email);
        authService.changePassword(email, request);
        return ResponseEntity.ok(Map.of("message", "Contraseña cambiada con éxito."));
    }

    private List<String> resolveRoles(UserEntity user) {

        List<String> roles = new ArrayList<>();

        if (user.getRole() == UserRole.USER_APP) {
            roles.add("USER_APP");
        }

        if (user.getRole() == UserRole.USER_JPL) {
            roles.add("USER_JPL");
        }

        if (user.getRole() == UserRole.USER_SUPERVISOR) {
            roles.add("USER_SUPERVISOR");
        }

        if (user.getRole() == UserRole.USER_ADMIN) {
            roles.add("USER_ADMIN");
        }

        return roles;
    }
}