package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.dto.user.UserResponseDTO;
import com.evecta.auth.dto.user.UserUpdateDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.IUserRepository;
import com.evecta.auth.util.TestDataBuilder;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private IUserRepository userRepository;

    @Mock
    private AuthService authService;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @Mock
    private AuditoriaService auditoriaService;

    @InjectMocks
    private UserService userService;

    private UserEntity activeUser;
    private UserEntity inactiveUser;
    private UserEntity userAppUser;
    private UserCreateDTO userCreateDTO;
    private UserUpdateDTO userUpdateDTO;
    private static final String REQUESTING_EMAIL = "admin@example.com";
    private static final String TEST_RUT = "11111111";
    private static final String TEST_DV = "1";

    @BeforeEach
    void setUp() {
        activeUser = TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "existing@example.com", TEST_RUT, TEST_DV);
        inactiveUser = TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "inactive@example.com", "22222222", "2");
        inactiveUser.setActive(false);
        userAppUser = TestDataBuilder.createUserEntity(UserRole.USER_APP, "userapp@example.com", "33333333", "3");

        userCreateDTO = TestDataBuilder.createUserCreateDTO();

        userUpdateDTO = UserUpdateDTO.builder()
                .name("UpdatedName")
                .email("updated@example.com")
                .build();
    }

    @Test
    void createUser_datosValidos_retornaUserResponse() {
        String rut = userCreateDTO.getRut();
        String dv = userCreateDTO.getDv();

        when(userRepository.findByRut(rut)).thenReturn(Optional.empty());
        when(userRepository.existsByEmail(userCreateDTO.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(userCreateDTO.getPassword())).thenReturn("encoded-password");
        when(userRepository.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = userService.createOrReactivateUser(userCreateDTO, REQUESTING_EMAIL);

        assertNotNull(result);
        assertEquals(rut, result.getRut());
        assertEquals(userCreateDTO.getName(), result.getName());
        assertEquals(userCreateDTO.getEmail(), result.getEmail());
        assertEquals(userCreateDTO.getRole(), result.getRole());
        assertTrue(result.isActive());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(REQUESTING_EMAIL),
                eq("USUARIO_CREADO"),
                eq("users"),
                eq(rut),
                anyMap());
    }

    @Test
    void createUser_rutDuplicado_lanzaExcepcion() {
        when(userRepository.findByRut(userCreateDTO.getRut())).thenReturn(Optional.of(activeUser));

        assertThrows(IllegalArgumentException.class,
                () -> userService.createOrReactivateUser(userCreateDTO, REQUESTING_EMAIL));
    }

    @Test
    void createUser_rutInvalido_lanzaExcepcion() {
        UserCreateDTO invalidRutDTO = UserCreateDTO.builder()
                .rut("12345678")
                .dv("0")
                .name("Test")
                .lastName("User")
                .email("invalidrut@example.com")
                .role(UserRole.USER_ADMIN)
                .password("TestPass123")
                .build();

        assertThrows(IllegalArgumentException.class,
                () -> userService.createOrReactivateUser(invalidRutDTO, REQUESTING_EMAIL));
    }

    @Test
    void createUser_usuarioInactivo_reactiva() {
        UserCreateDTO reactivateDTO = TestDataBuilder.createUserCreateDTO();
        String rut = reactivateDTO.getRut();
        String dv = reactivateDTO.getDv();

        UserEntity inactiveExisting = TestDataBuilder.createUserEntity(UserRole.USER_APP, "old@example.com", rut, dv);
        inactiveExisting.setActive(false);

        when(userRepository.findByRut(rut)).thenReturn(Optional.of(inactiveExisting));
        when(userRepository.existsByEmail(reactivateDTO.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(reactivateDTO.getPassword())).thenReturn("encoded-password");
        when(userRepository.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = userService.createOrReactivateUser(reactivateDTO, REQUESTING_EMAIL);

        assertTrue(result.isActive());
        assertEquals(reactivateDTO.getName(), result.getName());
        assertEquals(reactivateDTO.getEmail(), result.getEmail());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(REQUESTING_EMAIL),
                eq("USUARIO_ACTIVADO"),
                eq("users"),
                eq(rut),
                anyMap());
    }

    @Test
    void deactivateUser_rutValido_desactivaYAudita() {
        when(userRepository.findByRut("22222222")).thenReturn(Optional.of(inactiveUser));
        when(userRepository.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));
        inactiveUser.setActive(true);

        UserResponseDTO result = userService.deactivateUserByRut("22222222", REQUESTING_EMAIL);

        assertFalse(result.isActive());
        verify(authService).revokeAllUserTokens(inactiveUser);
        verify(auditoriaService).registrarAccionAsincrona(
                eq(REQUESTING_EMAIL),
                eq("USUARIO_DESACTIVADO"),
                eq("users"),
                eq("22222222"),
                anyMap());
    }

    @Test
    void deactivateUser_autoDesactivacion_lanzaExcepcion() {
        when(userRepository.findByRut(TEST_RUT)).thenReturn(Optional.of(activeUser));

        assertThrows(IllegalStateException.class,
                () -> userService.deactivateUserByRut(TEST_RUT, activeUser.getEmail()));
    }

    @Test
    void activateUser_rutValido_activaYAudita() {
        when(userRepository.findByRut("22222222")).thenReturn(Optional.of(inactiveUser));
        when(userRepository.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponseDTO result = userService.activateUserByRut("22222222", REQUESTING_EMAIL);

        assertTrue(result.isActive());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(REQUESTING_EMAIL),
                eq("USUARIO_ACTIVADO"),
                eq("users"),
                eq("22222222"),
                anyMap());
    }

    @Test
    void updateUser_datosValidos_actualizaYAudita() {
        when(userRepository.findActiveByRut(TEST_RUT)).thenReturn(Optional.of(activeUser));
        when(userRepository.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponseDTO result = userService.updateUser(TEST_RUT, userUpdateDTO, REQUESTING_EMAIL);

        assertEquals("UpdatedName", result.getName());
        assertEquals("updated@example.com", result.getEmail());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(REQUESTING_EMAIL),
                eq("USUARIO_ACTUALIZADO"),
                eq("users"),
                eq(TEST_RUT),
                anyMap());
    }

    @Test
    void updateUserRole_rolValido_cambiaRolYAudita() {
        when(userRepository.findActiveByRut(TEST_RUT)).thenReturn(Optional.of(activeUser));
        when(userRepository.save(any(UserEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        UserResponseDTO result = userService.updateUserRole(TEST_RUT, "USER_SUPERVISOR", REQUESTING_EMAIL);

        assertEquals("USER_SUPERVISOR", result.getRole());
        verify(auditoriaService).registrarAccionAsincrona(
                eq(REQUESTING_EMAIL),
                eq("ROL_ACTUALIZADO"),
                eq("users"),
                eq(TEST_RUT),
                anyMap());
    }

    @Test
    void findUserByRut_usuarioExistente_retornaDTO() {
        when(userRepository.findActiveByRut(TEST_RUT)).thenReturn(Optional.of(activeUser));

        UserResponseDTO result = userService.findUserByRut(TEST_RUT);

        assertNotNull(result);
        assertEquals(activeUser.getEmail(), result.getEmail());
        assertEquals(activeUser.getName(), result.getName());
    }

    @Test
    void findAllUsers_paginacion_retornaPagina() {
        Pageable pageable = PageRequest.of(0, 10);
        Page<UserEntity> userPage = new PageImpl<>(List.of(activeUser));
        when(userRepository.findAll(pageable)).thenReturn(userPage);

        Page<UserResponseDTO> result = userService.findAllUsers(pageable, null);

        assertNotNull(result);
        assertEquals(1, result.getContent().size());
        assertEquals(activeUser.getEmail(), result.getContent().get(0).getEmail());
    }

    @Test
    void findAllFiscalizadores_retornaLista() {
        when(userRepository.findAllFiscalizadores()).thenReturn(List.of(userAppUser));

        List<UserResponseDTO> result = userService.findAllFiscalizadores();

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("USER_APP", result.get(0).getRole());
    }
}
