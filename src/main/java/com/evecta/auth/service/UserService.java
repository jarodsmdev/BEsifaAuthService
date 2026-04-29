package com.evecta.auth.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.evecta.auth.dto.RutValidator;
import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.dto.user.UserUpdateDTO;
import com.evecta.auth.dto.user.UserResponseDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.IUserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final IUserRepository userRepository;
    private final AuthService authService;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    @SuppressWarnings("null")
    public UserEntity createOrReactivateUser(UserCreateDTO userDTO) {
        log.info("Creando usuario con RUT: {}", userDTO.getRut());

        // Validar RUT
        if (!RutValidator.validarRut(userDTO.getRut(), userDTO.getDv())) {
            throw new IllegalArgumentException("RUT inválido");
        }

        UserEntity existingUser = userRepository.findByRut(userDTO.getRut()).orElse(null);

        if (existingUser != null) {

            if (existingUser.isActive()) {
                throw new IllegalArgumentException("Usuario con este RUT ya existe");
            }

            // Reactivar usuario
            if (!existingUser.getEmail().equals(userDTO.getEmail()) &&
                    userRepository.existsByEmail(userDTO.getEmail())) {
                throw new IllegalArgumentException("Email ya registrado");
            }

            existingUser.activate();
            existingUser.setName(userDTO.getName());
            existingUser.setLastName(userDTO.getLastName());
            existingUser.setBirthDate(userDTO.getBirthDate());
            existingUser.setEmail(userDTO.getEmail());
            existingUser.setPhone(userDTO.getPhone());
            existingUser.setPassword(encodePassword(userDTO.getPassword()));

            // Mantenemos el rol que ya tenía si es una reactivación
            // existingUser.setRole(existingUser.getRole()); // No hace falta cambiarlo

            return userRepository.save(existingUser);
        }

        // Validar email
        if (userRepository.existsByEmail(userDTO.getEmail())) {
            throw new IllegalArgumentException("Email ya se encuentra registrado");
        }

        // Crear usuario
        UserEntity user = UserEntity.builder()
                .rut(userDTO.getRut())
                .dv(userDTO.getDv())
                .name(userDTO.getName())
                .lastName(userDTO.getLastName())
                .birthDate(userDTO.getBirthDate())
                .email(userDTO.getEmail())
                .phone(userDTO.getPhone())
                .password(encodePassword(userDTO.getPassword()))
                .role(userDTO.getRole())
                .isActive(true)
                .build();

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public UserResponseDTO findUserByRut(String rut) {
        log.info("Buscando usuario por RUT: {}", rut);

        UserEntity user = userRepository.findActiveByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado o inactivo"));

        return UserResponseDTO.fromEntity(user);
    }

    @Transactional(readOnly = true)
    public UserResponseDTO findUserByEmail(String email) {
        log.info("Buscando usuario por email: {}", email);

        UserEntity user = userRepository.findActiveByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado o inactivo"));

        return UserResponseDTO.fromEntity(user);
    }

    @Transactional(readOnly = true)
    public List<UserResponseDTO> findAllUsers() {
        log.info("Listando todos los usuarios (activos e inactivos)");

        return userRepository.findAll()
                .stream()
                .map(UserResponseDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<UserResponseDTO> findAllActiveUsers() {
        log.info("Listando todos los usuarios activos");

        return userRepository.findAllByIsActiveTrue()
                .stream()
                .map(UserResponseDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Transactional
    public UserResponseDTO deactivateUserByRut(String rut, String requestingUserEmail) {
        log.info("Desactivando usuario con RUT: {}", rut);

        UserEntity user = userRepository.findByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado con RUT: " + rut));

        if (user.getEmail().equals(requestingUserEmail)) {
            throw new IllegalStateException("No puedes desactivar tu propia cuenta");
        }

        if (!user.isActive()) {
            throw new IllegalStateException("El usuario ya está desactivado");
        }

        authService.revokeAllUserTokens(user);

        user.deactivate();
        UserEntity updatedUser = userRepository.save(user);
        log.info("Usuario desactivado exitosamente: {}", rut);
        return UserResponseDTO.fromEntity(updatedUser);
    }

    @Transactional
    public UserResponseDTO activateUserByRut(String rut) {
        log.info("Activando usuario con RUT: {}", rut);

        UserEntity user = userRepository.findByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado con RUT: " + rut));

        if (user.isActive()) {
            throw new IllegalStateException("El usuario ya está activo");
        }

        user.activate();
        UserEntity updatedUser = userRepository.save(user);
        log.info("Usuario activado exitosamente: {}", rut);
        return UserResponseDTO.fromEntity(updatedUser);
    }

    @Transactional
    @SuppressWarnings("null")
    public UserResponseDTO updateUser(String rut, UserUpdateDTO userDTO) {
        log.info("Actualizando usuario con RUT: {}", rut);

        UserEntity user = userRepository.findActiveByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado o inactivo"));

        // Actualizar campos permitidos
        if (userDTO.getName() != null) user.setName(userDTO.getName());
        if (userDTO.getLastName() != null) user.setLastName(userDTO.getLastName());
        if (userDTO.getEmail() != null && !userDTO.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(userDTO.getEmail())) {
                throw new IllegalArgumentException("Email ya registrado");
            }
            user.setEmail(userDTO.getEmail());
        }
        if (userDTO.getPhone() != null) user.setPhone(userDTO.getPhone());
        
        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            user.setPassword(encodePassword(userDTO.getPassword()));
        }

        UserEntity updatedUser = userRepository.save(user);
        return UserResponseDTO.fromEntity(updatedUser);
    }

    @Transactional
    public UserResponseDTO updateUserRole(String rut, String roleName) {
        log.info("Actualizando ROL para RUT: {} a {}", rut, roleName);
        UserEntity user = userRepository.findActiveByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado o inactivo"));

        try {
            UserRole role = UserRole.valueOf(roleName.toUpperCase());
            user.setRole(role);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Rol no válido: " + roleName);
        }

        UserEntity updatedUser = userRepository.save(user);
        return UserResponseDTO.fromEntity(updatedUser);
    }

    private String encodePassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    @Transactional
    public UserResponseDTO deactivateUserByEmail(String email, String requestingUserEmail) {
        log.info("Desactivando usuario con email: {}", email);

        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado con email: " + email));

        if (user.getEmail().equals(requestingUserEmail)) {
            throw new IllegalStateException("No puedes desactivar tu propia cuenta");
        }

        if (!user.isActive()) {
            throw new IllegalStateException("El usuario ya está inactivo");
        }

        authService.revokeAllUserTokens(user);

        user.deactivate();
        UserEntity updatedUser = userRepository.save(user);
        log.info("Usuario desactivado exitosamente: {}", email);
        return UserResponseDTO.fromEntity(updatedUser);
    }
}