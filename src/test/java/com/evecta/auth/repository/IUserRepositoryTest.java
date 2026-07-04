package com.evecta.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;

@DataJpaTest
@DisplayName("IUserRepository")
class IUserRepositoryTest {

    @Autowired
    private IUserRepository userRepository;

    private UserEntity activeUser;
    private UserEntity inactiveUser;
    private UserEntity fiscalizador;

    @BeforeEach
    void setUp() {
        activeUser = new UserEntity();
        activeUser.setRut("11111111");
        activeUser.setDv("1");
        activeUser.setName("Active");
        activeUser.setLastName("User");
        activeUser.setEmail("active@test.com");
        activeUser.setPassword("$2a$10$hash");
        activeUser.setRole(UserRole.USER_ADMIN);
        activeUser.setActive(true);
        userRepository.save(activeUser);

        inactiveUser = new UserEntity();
        inactiveUser.setRut("22222222");
        inactiveUser.setDv("2");
        inactiveUser.setName("Inactive");
        inactiveUser.setLastName("User");
        inactiveUser.setEmail("inactive@test.com");
        inactiveUser.setPassword("$2a$10$hash");
        inactiveUser.setRole(UserRole.USER_ADMIN);
        inactiveUser.setActive(false);
        userRepository.save(inactiveUser);

        fiscalizador = new UserEntity();
        fiscalizador.setRut("33333333");
        fiscalizador.setDv("3");
        fiscalizador.setName("Fiscalizador");
        fiscalizador.setLastName("Test");
        fiscalizador.setEmail("fiscalizador@test.com");
        fiscalizador.setPassword("$2a$10$hash");
        fiscalizador.setRole(UserRole.USER_APP);
        fiscalizador.setActive(true);
        userRepository.save(fiscalizador);
    }

    @Test
    @DisplayName("findActiveByRut con usuario activo lo encuentra")
    void findActiveByRut_usuarioActivo_retornaUsuario() {
        Optional<UserEntity> found = userRepository.findActiveByRut("11111111");
        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("active@test.com");
    }

    @Test
    @DisplayName("findActiveByRut con usuario inactivo no lo encuentra")
    void findActiveByRut_usuarioInactivo_retornaVacio() {
        Optional<UserEntity> found = userRepository.findActiveByRut("22222222");
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("findByRut encuentra cualquier usuario (activo o inactivo)")
    void findByRut_usuarioInactivo_retornaUsuario() {
        Optional<UserEntity> found = userRepository.findByRut("22222222");
        assertThat(found).isPresent();
    }

    @Test
    @DisplayName("findByRut con RUT inexistente retorna vacío")
    void findByRut_rutInexistente_retornaVacio() {
        Optional<UserEntity> found = userRepository.findByRut("00000000");
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("existsByRut con RUT existente retorna true")
    void existsByRut_rutExistente_retornaTrue() {
        assertThat(userRepository.existsByRut("11111111")).isTrue();
    }

    @Test
    @DisplayName("existsByEmail con email existente retorna true")
    void existsByEmail_emailExistente_retornaTrue() {
        assertThat(userRepository.existsByEmail("active@test.com")).isTrue();
    }

    @Test
    @DisplayName("findAllByIsActiveTrue solo retorna usuarios activos")
    void findAllByIsActiveTrue_soloActivos() {
        var usuarios = userRepository.findAllByIsActiveTrue();
        assertThat(usuarios).hasSize(2);
        assertThat(usuarios).extracting(UserEntity::getEmail)
            .containsExactlyInAnyOrder("active@test.com", "fiscalizador@test.com");
    }

    @Test
    @DisplayName("findAllFiscalizadores solo retorna USER_APP activos")
    void findAllFiscalizadores_soloUserApp() {
        var fiscalizadores = userRepository.findAllFiscalizadores();
        assertThat(fiscalizadores).hasSize(1);
        assertThat(fiscalizadores.get(0).getEmail()).isEqualTo("fiscalizador@test.com");
    }

    @Test
    @DisplayName("findByFilters con search retorna resultados paginados")
    void findByFilters_conSearch_retornaResultados() {
        Page<UserEntity> page = userRepository.findByFilters("active", PageRequest.of(0, 10));
        assertThat(page.getContent()).isNotEmpty();
        assertThat(page.getContent().get(0).getEmail()).contains("active");
    }

    @Test
    @DisplayName("findByEmail con email existente retorna usuario")
    void findByEmail_emailExistente_retornaUsuario() {
        Optional<UserEntity> found = userRepository.findByEmail("active@test.com");
        assertThat(found).isPresent();
    }

    @Test
    @DisplayName("findActiveByEmail con email activo retorna usuario")
    void findActiveByEmail_emailActivo_retornaUsuario() {
        Optional<UserEntity> found = userRepository.findActiveByEmail("active@test.com");
        assertThat(found).isPresent();
    }

    @Test
    @DisplayName("findActiveByEmail con email inactivo retorna vacío")
    void findActiveByEmail_emailInactivo_retornaVacio() {
        Optional<UserEntity> found = userRepository.findActiveByEmail("inactive@test.com");
        assertThat(found).isEmpty();
    }
}
