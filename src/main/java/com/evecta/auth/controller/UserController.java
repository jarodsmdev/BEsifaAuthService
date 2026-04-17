package com.evecta.auth.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.evecta.auth.dto.auth.AuthResponseDTO;
import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.dto.user.UserResponseDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.service.AuthService;
import com.evecta.auth.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/auth/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final AuthService authService;

    @PostMapping
    public ResponseEntity<UserResponseDTO> registerUser(@Valid @RequestBody UserCreateDTO userDTO) {

        log.info("Registro usuario RUT: {}", userDTO.getRut());

        UserEntity user = userService.createOrReactivateUser(userDTO);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserResponseDTO.fromEntity(user));
    }

    /**
     * Endpoint para buscar un usuario por su RUT. Devuelve un DTO con los datos del usuario.
     * @param rut RUT del usuario a buscar (Ej: 12345678)
     * @return ResponseEntity con el DTO del usuario encontrado o un error si no se encuentra.
     */
    @GetMapping("/{rut}")
    public ResponseEntity<UserResponseDTO> getUserByRut(@PathVariable String rut) {
        log.info("Recibida solicitud de búsqueda por RUT: {}", rut);
        UserResponseDTO user = userService.findUserByRut(rut);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserResponseDTO> getUserByEmail(@PathVariable String email) {
        log.info("Recibida solicitud de búsqueda por email: {}", email);
        UserResponseDTO user = userService.findUserByEmail(email);
        return ResponseEntity.ok(user);
    }

    @GetMapping()
    public ResponseEntity<List<UserResponseDTO>> getAllActiveUsers() {
        log.info("Recibida solicitud para listar todos los usuarios activos");
        List<UserResponseDTO> users = userService.findAllActiveUsers();
        return ResponseEntity.ok(users);
    }

    @DeleteMapping("/{rut}")
    public ResponseEntity<Void> deactivateUser(@PathVariable String rut) {
        log.info("Recibida solicitud para desactivar usuario: {}", rut);
        userService.deactivateUser(rut);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{rut}")
    public ResponseEntity<UserResponseDTO> updateUser(
            @PathVariable String rut,
            @Valid @RequestBody UserCreateDTO userDTO) {
        log.info("Recibida solicitud de actualización para RUT: {}", rut);
        UserResponseDTO updatedUser = userService.updateUser(rut, userDTO);
        return ResponseEntity.ok(updatedUser);
    }
}