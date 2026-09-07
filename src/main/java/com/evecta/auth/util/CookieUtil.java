package com.evecta.auth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Utilidad para manejar cookies HttpOnly de autenticación.
 *
 * <p>Las cookies HttpOnly no son accesibles desde JavaScript, lo que protege los tokens JWT contra
 * ataques XSS. Las cookies se envían automáticamente en cada petición HTTP al mismo dominio.
 *
 * <p>Configuración de seguridad: - HttpOnly: No accesible desde JavaScript (protección XSS) -
 * Secure: Solo se envían por HTTPS - SameSite=Strict: No se envían en peticiones cross-origin
 * (protección CSRF) - Path: Restringe las rutas donde es válida la cookie
 */
public final class CookieUtil {

  // Nombre de las cookies de autenticación
  public static final String ACCESS_TOKEN_COOKIE = "access_token";
  public static final String REFRESH_TOKEN_COOKIE = "refresh_token";

  // Paths para las cookies
  private static final String ACCESS_TOKEN_PATH = "/";
  private static final String REFRESH_TOKEN_PATH = "/auth/api/v1";

  // Tiempo de vida en segundos (0 = eliminar cookie)
  private static final int MAX_AGE_ACCESS_TOKEN = 300; // 5 minutos
  private static final int MAX_AGE_REFRESH_TOKEN = 72000; // 20 horas

  private CookieUtil() {
    // Constructor privado para clase utilitaria
  }

  /**
   * Establece la cookie del access token (JWT) en la respuesta HTTP.
   *
   * @param response Respuesta HTTP donde se agrega la cookie
   * @param token Token JWT a almacenar
   */
  public static void setAccessTokenCookie(HttpServletResponse response, String token) {
    Cookie cookie = new Cookie(ACCESS_TOKEN_COOKIE, token);
    cookie.setHttpOnly(true); // No accesible desde JavaScript
    cookie.setSecure(true); // Solo HTTPS
    cookie.setPath(ACCESS_TOKEN_PATH);
    cookie.setMaxAge(MAX_AGE_ACCESS_TOKEN);
    cookie.setAttribute("SameSite", "Strict");
    response.addCookie(cookie);
  }

  /**
   * Establece la cookie del refresh token en la respuesta HTTP.
   *
   * @param response Respuesta HTTP donde se agrega la cookie
   * @param refreshToken Refresh token a almacenar
   */
  public static void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
    Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE, refreshToken);
    cookie.setHttpOnly(true); // No accesible desde JavaScript
    cookie.setSecure(true); // Solo HTTPS
    cookie.setPath(REFRESH_TOKEN_PATH); // Solo para endpoints de auth
    cookie.setMaxAge(MAX_AGE_REFRESH_TOKEN);
    cookie.setAttribute("SameSite", "Strict");
    response.addCookie(cookie);
  }

  /**
   * Elimina la cookie del access token (establece MaxAge en 0).
   *
   * @param response Respuesta HTTP donde se elimina la cookie
   */
  public static void clearAccessTokenCookie(HttpServletResponse response) {
    Cookie cookie = new Cookie(ACCESS_TOKEN_COOKIE, "");
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath(ACCESS_TOKEN_PATH);
    cookie.setMaxAge(0); // Eliminar cookie
    cookie.setAttribute("SameSite", "Strict");
    response.addCookie(cookie);
  }

  /**
   * Elimina la cookie del refresh token (establece MaxAge en 0).
   *
   * @param response Respuesta HTTP donde se elimina la cookie
   */
  public static void clearRefreshTokenCookie(HttpServletResponse response) {
    Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE, "");
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath(REFRESH_TOKEN_PATH);
    cookie.setMaxAge(0); // Eliminar cookie
    cookie.setAttribute("SameSite", "Strict");
    response.addCookie(cookie);
  }

  /**
   * Extrae el valor de una cookie por su nombre desde la petición HTTP.
   *
   * @param request Petición HTTP de donde se lee la cookie
   * @param cookieName Nombre de la cookie a buscar
   * @return Valor de la cookie o null si no existe
   */
  public static String getCookieValue(HttpServletRequest request, String cookieName) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }

    for (Cookie cookie : cookies) {
      if (cookie.getName().equals(cookieName)) {
        return cookie.getValue();
      }
    }
    return null;
  }

  /**
   * Obtiene el access token desde las cookies de la petición.
   *
   * @param request Petición HTTP
   * @return Access token JWT o null si no existe
   */
  public static String getAccessToken(HttpServletRequest request) {
    return getCookieValue(request, ACCESS_TOKEN_COOKIE);
  }

  /**
   * Obtiene el refresh token desde las cookies de la petición.
   *
   * @param request Petición HTTP
   * @return Refresh token o null si no existe
   */
  public static String getRefreshToken(HttpServletRequest request) {
    return getCookieValue(request, REFRESH_TOKEN_COOKIE);
  }
}
