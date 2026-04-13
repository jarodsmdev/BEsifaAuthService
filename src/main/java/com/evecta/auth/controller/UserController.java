package com.evecta.auth.controller;

import com.evecta.auth.dto.UserCreateDTO;
import com.evecta.auth.dto.UserResponseDTO;
import com.evecta.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/auth/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    @PostMapping()
    public ResponseEntity<UserResponseDTO> registerUser(@Valid @RequestBody UserCreateDTO userDTO) {
        log.info("Recibida solicitud de registro para RUT: {}", userDTO.getRut());
        UserResponseDTO createdUser = userService.createUser(userDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
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