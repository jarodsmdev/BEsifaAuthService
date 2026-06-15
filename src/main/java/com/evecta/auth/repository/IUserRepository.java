package com.evecta.auth.repository;

import com.evecta.auth.model.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IUserRepository extends JpaRepository<UserEntity, UUID> {

    /**
     * Devuelve un Optional de UserEntity basado en el RUT, solo si el usuario está
     * activo.
     *
     * @param rut El RUT del usuario a buscar.
     * @return Optional de UserEntity si se encuentra un usuario activo con el RUT
     * dado, de lo contrario un Optional vacío.
     */
    @Query("SELECT u FROM UserEntity u WHERE u.rut =:rut AND u.isActive = true")
    Optional<UserEntity> findActiveByRut(String rut);

    /**
     * Devuelve un Optional de UserEntity basado en el RUT, sin importar si el
     * usuario está activo o no.
     *
     * @param rut El RUT del usuario a buscar.
     * @return Optional de UserEntity si se encuentra un usuario con el RUT dado, de
     * lo contrario un Optional vacío.
     */
    Optional<UserEntity> findByRut(String rut);

    /**
     * Devuelve un Optional de UserEntity sólo si el usuario se encuentra activo.
     *
     * @return
     */
    List<UserEntity> findAllByIsActiveTrue();

    boolean existsByRut(String rut);

    boolean existsByEmail(String email);

    Optional<UserEntity> findByEmail(String email);

    @Query("SELECT u FROM UserEntity u WHERE u.email = :email AND u.isActive = true")
    Optional<UserEntity> findActiveByEmail(String email);

    // devuelve todos los usuarios fiscalizadores
    @Query("SELECT u FROM UserEntity u WHERE u.role = 'USER_APP'")
    List<UserEntity> findAllFiscalizadores();

    /**
     * Devuelve una página de usuarios filtrados por una cadena de búsqueda,
     * ignorando mayúsculas y minúsculas, buscando en rut, nombre, apellidos o email.
     */
    @Query("SELECT u FROM UserEntity u WHERE " +
           "LOWER(u.rut) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.name) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :search, '%'))")
    Page<UserEntity> findByFilters(@Param("search") String search, Pageable pageable);
}
