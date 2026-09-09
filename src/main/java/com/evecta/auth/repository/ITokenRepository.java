package com.evecta.auth.repository;

import com.evecta.auth.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface ITokenRepository extends JpaRepository<Token, Long> {

    /**
     * Busca un token por su valor en texto plano.
     *
     * <p>SOLO para access tokens JWT (BEARER), que se almacenan en texto plano
     * porque se validan por firma criptográfica (HMAC-SHA). Un JWT comprometido
     * por acceso a la BD tiene impacto acotado: expire en el corto plazo y solo
     * es usable hasta su expiración.
     *
     * <p>Los refresh tokens se buscan con {@link #findByTokenHash(String)} y NUNCA
     * se persisten en texto plano.
     *
     * @param token Token JWT en texto plano
     * @return Optional con el token encontrado
     */
    Optional<Token> findByToken(String token);

    /**
     * Busca un token por el hash SHA-256 de su valor.
     *
     * <p>Se usa para refresh tokens: en BD solo existe el hash (unidireccional),
     * nunca el texto plano. Si la BD es comprometida, el atacante no puede
     * derivar el token original ni emitir nuevos tokens con él.
     *
     * @param tokenHash Hash SHA-256 hexadecimal del token
     * @return Optional con el token encontrado
     */
    Optional<Token> findByTokenHash(String tokenHash);

    /**
     * Busca todos los tokens de una familia de rotación.
     *
     * <p>Se usa al detectar reutilización de un refresh token (posible compromiso)
     * para revocar TODA la cadena de tokens de la sesión.
     *
     * @param familyId Identificador de la familia de rotación
     * @return Lista de tokens pertenecientes a la familia
     */
    List<Token> findAllByFamilyId(String familyId);

    List<Token> findAllByUser_RutAndExpiredFalseAndRevokedFalse(String rut);

    List<Token> findAllByUser_Rut(String rut);

    Page<Token> findAllByOrderByIdTokenDesc(Pageable pageable);
}