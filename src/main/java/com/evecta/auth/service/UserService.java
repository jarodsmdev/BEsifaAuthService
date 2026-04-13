package com.evecta.auth.service;

import com.evecta.auth.dto.RutValidator;
import com.evecta.auth.dto.UserCreateDTO;
import com.evecta.auth.dto.UserResponseDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final IUserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public UserResponseDTO createUser(UserCreateDTO userDTO) {
        log.info("Creando usuario con RUT: {}", userDTO.getRut());

        // Validar RUT
        if (!RutValidator.validarRut(userDTO.getRut(), userDTO.getDv())) {
            log.warn("RUT inválido: {}-{}", userDTO.getRut(), userDTO.getDv());
            throw new IllegalArgumentException("RUT inválido");
        }

        // Buscar usuario existente por RUT
        UserEntity existingUser = userRepository.findByRut(userDTO.getRut()).orElse(null);

        if (existingUser != null) {

            if (existingUser.isActive()) {
                log.warn("El usuario con RUT {} ya existe y está activo", userDTO.getRut());
                throw new IllegalArgumentException("Usuario con este RUT ya existe");
            }

            // Usuario existe pero está inactivo → reactivar
            log.info("Usuario con RUT {} está inactivo. Se procederá a reactivarlo", userDTO.getRut());

            // Validar email (porque es UNIQUE)
            if (!existingUser.getEmail().equals(userDTO.getEmail()) &&
                    userRepository.existsByEmail(userDTO.getEmail())) {
                throw new IllegalArgumentException("Email ya registrado");
            }

            existingUser.activate();
            existingUser.setName(userDTO.getName());
            existingUser.setLastName(userDTO.getLastName());
            existingUser.setBirthDate(userDTO.getBirthDate());
            existingUser.setEmail(userDTO.getEmail());
            existingUser.setPassword(encodePassword(userDTO.getPassword()));

            UserEntity updatedUser = userRepository.save(existingUser);

            log.info("Usuario reactivado exitosamente con RUT: {}", updatedUser.getRut());

            return UserResponseDTO.fromEntity(updatedUser);
        }

        // Validar email para usuario nuevo
        if (userRepository.existsByEmail(userDTO.getEmail())) {
            log.warn("El email {} ya está registrado", userDTO.getEmail());
            throw new IllegalArgumentException("Email ya se encuentra registrado");
        }

        // Crear nuevo usuario
        UserEntity user = UserEntity.builder()
                .rut(userDTO.getRut())
                .dv(userDTO.getDv().toUpperCase())
                .name(userDTO.getName())
                .lastName(userDTO.getLastName())
                .birthDate(userDTO.getBirthDate())
                .email(userDTO.getEmail())
                .password(encodePassword(userDTO.getPassword()))
                .isActive(true)
                .build();

        UserEntity savedUser = userRepository.save(user);

        log.info("Usuario creado exitosamente con RUT: {}", savedUser.getRut());

        return UserResponseDTO.fromEntity(savedUser);
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
    public List<UserResponseDTO> findAllActiveUsers() {
        log.info("Listando todos los usuarios activos");

        return userRepository.findAllByIsActiveTrue()
                .stream()
                .map(UserResponseDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Transactional
    public void deactivateUser(String rut) {
        log.info("Desactivando usuario con RUT: {}", rut);

        UserEntity user = userRepository.findByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        if (!user.isActive()) {
            throw new IllegalStateException("El usuario ya está inactivo");
        }

        user.deactivate();
        userRepository.save(user);
        log.info("Usuario desactivado exitosamente: {}", rut);
    }

    @Transactional
    public UserResponseDTO updateUser(String rut, UserCreateDTO userDTO) {
        log.info("Actualizando usuario con RUT: {}", rut);

        // Buscar usuario sólo si está activo, para evitar actualizar usuarios inactivos
        UserEntity user = userRepository.findActiveByRut(rut)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado o inactivo"));

        // Actualizar campos permitidos
        if (userDTO.getName() != null) user.setName(userDTO.getName());
        if (userDTO.getLastName() != null) user.setLastName(userDTO.getLastName());
        if (userDTO.getBirthDate() != null) user.setBirthDate(userDTO.getBirthDate());
        if (userDTO.getEmail() != null && !userDTO.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(userDTO.getEmail())) {
                throw new IllegalArgumentException("Email ya registrado");
            }
            user.setEmail(userDTO.getEmail());
        }
        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            user.setPassword(encodePassword(userDTO.getPassword()));
        }

        UserEntity updatedUser = userRepository.save(user);
        log.info("Usuario actualizado exitosamente: {}", rut);

        return UserResponseDTO.fromEntity(updatedUser);
    }

    private String encodePassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
}