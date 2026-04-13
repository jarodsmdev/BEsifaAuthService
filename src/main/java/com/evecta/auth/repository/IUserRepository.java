package com.evecta.auth.repository;

import com.evecta.auth.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IUserRepository extends JpaRepository<UserEntity, String> {

    /**
     * Devuelve un Optional de UserEntity basado en el RUT, solo si el usuario está activo.
     * @param rut El RUT del usuario a buscar.
     * @return Optional de UserEntity si se encuentra un usuario activo con el RUT dado, de lo contrario un Optional vacío.
     */
    @Query("SELECT u FROM UserEntity u WHERE u.rut =:rut AND u.isActive = true")
    Optional<UserEntity> findActiveByRut(String rut);

    /**
     * Devuelve un Optional de UserEntity basado en el RUT, sin importar si el usuario está activo o no.
     * @param rut El RUT del usuario a buscar.
     * @return Optional de UserEntity si se encuentra un usuario con el RUT dado, de lo contrario un Optional vacío.
     */
    Optional<UserEntity> findByRut(String rut);

    /**
     * Devuelve un Optional de UserEntity sólo si el usuario se encuentra activo.
     * @return 
     */
    List<UserEntity> findAllByIsActiveTrue();

    boolean existsByRut(String rut);

    boolean existsByEmail(String email);

    Optional<UserEntity> findByEmail(String email);

    Optional<UserEntity> findActiveByEmail(String email);
}
