package com.evecta.auth.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.dto.user.UserUpdateDTO;
import com.evecta.auth.dto.user.UserResponseDTO;
import com.evecta.auth.model.UserEntity;
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

    @PostMapping
    public ResponseEntity<UserResponseDTO> registerUser(@Valid @RequestBody UserCreateDTO userDTO) {

        log.info("Registro usuario RUT: {}", userDTO.getRut());

        UserEntity user = userService.createOrReactivateUser(userDTO);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(UserResponseDTO.fromEntity(user));
    }

    /**
     * Endpoint para buscar un usuario por su RUT. Devuelve un DTO con los datos del
     * usuario.
     * 
     * @param rut RUT del usuario a buscar (Ej: 12345678)
     * @return ResponseEntity con el DTO del usuario encontrado o un error si no se
     *         encuentra.
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
    public ResponseEntity<List<UserResponseDTO>> getAllUsers() {
        log.info("Recibida solicitud para listar todos los usuarios");
        List<UserResponseDTO> users = userService.findAllUsers();
        return ResponseEntity.ok(users);
    }

    @DeleteMapping
    public ResponseEntity<UserResponseDTO> deactivateUser(
            Authentication authentication,
            @RequestParam(required = false) String rut,
            @RequestParam(required = false) String email) {
        String requestingUserEmail = authentication.getName();

        if (rut != null) {
            log.info("Desactivar por RUT: {}", rut);
            return ResponseEntity.ok(userService.deactivateUserByRut(rut, requestingUserEmail));
        } else if (email != null) {
            log.info("Desactivar por email: {}", email);
            return ResponseEntity.ok(userService.deactivateUserByEmail(email, requestingUserEmail));
        } else {
            throw new IllegalArgumentException("Debe proporcionar rut o email");
        }
    }

    @PatchMapping("/{rut}/activate")
    public ResponseEntity<UserResponseDTO> activateUser(@PathVariable String rut) {
        log.info("Activando por RUT: {}", rut);
        return ResponseEntity.ok(userService.activateUserByRut(rut));
    }

    @PatchMapping("/{rut}/role")
    public ResponseEntity<UserResponseDTO> updateUserRole(
            @PathVariable String rut,
            @RequestBody Map<String, String> body) {
        String roleName = body.get("role");
        return ResponseEntity.ok(userService.updateUserRole(rut, roleName));
    }

    @PutMapping("/{rut}")
    public ResponseEntity<UserResponseDTO> updateUser(
            @PathVariable String rut,
            @Valid @RequestBody UserUpdateDTO userDTO) {
        log.info("Recibida solicitud de actualización para RUT: {}", rut);
        UserResponseDTO updatedUser = userService.updateUser(rut, userDTO);
        return ResponseEntity.ok(updatedUser);
    }
}