package com.evecta.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utilidad para hashing unidireccional de tokens de seguridad.
 *
 * <p>Implementa SHA-256 simple y determinístico para refresh tokens opacos.
 *
 * <p><b>¿Por qué no se usa salt?</b> Un salt es necesario para secretos de baja
 * entropía (como contraseñas) para prevenir rainbow tables. Los refresh tokens
 * generados con {@code SecureRandom} de 64 bytes tienen 512 bits de entropía,
 * lo que los hace inmunes a ataques de rainbow table/inversión: no existe una
 * tabla que cubra 2^512 valores posibles. El hash determinístico además permite
 * búsqueda directa en BD por {@code tokenHash} sin recorrer todas las filas.
 *
 * <p>Almacenar solo el hash protege contra compromisos de la base de datos: un
 * atacante con acceso a la BD no puede derivar el token original (el hash es
 * unidireccional), por lo que no puede usarlo para emitir nuevos tokens.
 *
 * <p><b>Nota:</b> Los access tokens JWT NO se hashean porque se validan por
 * firma criptográfica (HMAC-SHA) y expiran en el corto plazo. El riesgo de
 * almacenarlos en texto plano es de bajo impacto frente al costo de no poder
 * revocarlos individualmente por estado (revocado/expirado).
 */
public final class TokenHashUtil {

    private static final String ALGORITHM = "SHA-256";

    private TokenHashUtil() {
        // Clase de utilidad, no instanciar
    }

    /**
     * Calcula el hash SHA-256 de un token.
     *
     * <p>Determinístico: el mismo token produce siempre el mismo hash, lo que
     * permite búsquedas directas en BD por {@code tokenHash}.
     *
     * @param token Token en texto plano a hashear
     * @return Hash SHA-256 codificado en Hexadecimal (64 caracteres en minúscula)
     * @throws IllegalArgumentException si el token es nulo o vacío
     */
    public static String hashToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("El token no puede ser nulo o vacío");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));

            // Convertir bytes a hexadecimal
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algoritmo SHA-256 no disponible", e);
        }
    }

    /**
     * Verifica si un token en texto plano coincide con un hash almacenado.
     *
     * <p>Usa comparación de tiempo constante ({@link MessageDigest#isEqual})
     * para prevenir ataques de timing: el tiempo de respuesta no revela cuántos
     * bytes coinciden entre el hash calculado y el almacenado.
     *
     * @param token      Token en texto plano a verificar
     * @param storedHash Hash SHA-256 hexadecimal almacenado en BD
     * @return true si el token coincide con el hash almacenado
     */
    public static boolean verifyToken(String token, String storedHash) {
        if (token == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }

        String computedHash = hashToken(token);

        // Comparación de tiempo constante para prevenir timing attacks
        return MessageDigest.isEqual(
            computedHash.getBytes(StandardCharsets.UTF_8),
            storedHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Convierte un array de bytes a su representación hexadecimal.
     *
     * @param bytes Array de bytes a convertir
     * @return String hexadecimal en minúsculas
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}