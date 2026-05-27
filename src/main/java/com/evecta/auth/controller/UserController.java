package com.evecta.auth.controller;

import java.util.List;
import java.util.Map;

import com.evecta.auth.dto.user.UpdateUserRoleDTO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
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
@Tag(
    name = "Gestión de Usuarios",
    description = "Endpoints para la administración de usuarios del sistema")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

  private final UserService userService;

  @Operation(
      summary = "Registrar o Reactivar un Usuario",
      description =
          "Crea un nuevo usuario en el sistema. Si el usuario ya existe con el mismo RUT y está inactivo, lo reactiva con la nueva información proporcionada. Valida que el RUT sea válido y que el email no esté en uso por otro usuario activo.")
  @ApiResponse(
      responseCode = "201",
      description = "Usuario creado o reactivado exitosamente.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "400",
      description =
          "Datos de entrada inválidos, como un RUT no válido, un email ya registrado, o un usuario que ya existe y está activo.",
      content = @Content())
  @PostMapping
  public ResponseEntity<UserResponseDTO> registerUser(@Valid @RequestBody UserCreateDTO userDTO) {

    log.info("Registro usuario RUT: {}", userDTO.getRut());

    UserEntity user = userService.createOrReactivateUser(userDTO);

    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponseDTO.fromEntity(user));
  }

  @Operation(
      summary = "Buscar Usuario por RUT",
      description =
          "Busca y devuelve un usuario activo por su RUT. El RUT debe ser proporcionado sin puntos y con dígito verificador.")
  @ApiResponse(
      responseCode = "200",
      description = "Usuario encontrado.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "404",
      description = "Usuario no encontrado o inactivo.",
      content = @Content())
  @GetMapping("/{rut}")
  public ResponseEntity<UserResponseDTO> getUserByRut(
      @Parameter(description = "RUT del usuario a buscar (Ej: 12345678)", required = true)
          @PathVariable
          String rut) {
    log.info("Recibida solicitud de búsqueda por RUT: {}", rut);
    UserResponseDTO user = userService.findUserByRut(rut);
    return ResponseEntity.ok(user);
  }

  @Operation(
      summary = "Buscar Usuario por Email",
      description = "Busca y devuelve un usuario activo por su dirección de correo electrónico.")
  @ApiResponse(
      responseCode = "200",
      description = "Usuario encontrado.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "404",
      description = "Usuario no encontrado o inactivo.",
      content = @Content())
  @GetMapping("/email/{email}")
  public ResponseEntity<UserResponseDTO> getUserByEmail(
      @Parameter(description = "Email del usuario a buscar", required = true) @PathVariable
          String email) {
    log.info("Recibida solicitud de búsqueda por email: {}", email);
    UserResponseDTO user = userService.findUserByEmail(email);
    return ResponseEntity.ok(user);
  }

  @Operation(
      summary = "Listar todos los Usuarios (Paginado)",
      description =
          "Devuelve una lista paginada de todos los usuarios del sistema, incluyendo activos e inactivos. Permite la ordenación y paginación estándar.")
  @GetMapping()
  public ResponseEntity<Page<UserResponseDTO>> getAllUsers(
      @ParameterObject
          @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC)
          Pageable pageable) {
    log.info(
        "Recibida solicitud para listar usuarios - página: {}, tamaño: {}",
        pageable.getPageNumber(),
        pageable.getPageSize());
    return ResponseEntity.ok(userService.findAllUsers(pageable));
  }

  @Operation(
      summary = "Listar todos los Fiscalizadores",
      description =
          "Devuelve una lista completa de todos los usuarios que tienen el rol de fiscalizador, sin paginación.")
  @GetMapping("/fiscalizadores")
  public ResponseEntity<List<UserResponseDTO>> getAllFiscalizadores() {
    log.info("Recibida solicitud para listar todos los usuarios fiscalizadores");
    List<UserResponseDTO> users = userService.findAllFiscalizadores();
    return ResponseEntity.ok(users);
  }

  @Operation(
      summary = "Desactivar un Usuario",
      description =
          "Desactiva un usuario por su RUT o Email. Un usuario no puede desactivar su propia cuenta. Al desactivar, también se revocan todos sus tokens de sesión activos.")
  @ApiResponse(
      responseCode = "200",
      description = "Usuario desactivado exitosamente.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "400",
      description =
          "Petición inválida (ej. intentar auto-desactivarse) o el usuario ya está inactivo.",
      content = @Content())
  @ApiResponse(responseCode = "404", description = "Usuario no encontrado.", content = @Content())
  @DeleteMapping
  public ResponseEntity<UserResponseDTO> deactivateUser(
      Authentication authentication,
      @Parameter(description = "RUT del usuario a desactivar") @RequestParam(required = false)
          String rut,
      @Parameter(description = "Email del usuario a desactivar") @RequestParam(required = false)
          String email) {
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

  @Operation(
      summary = "Activar un Usuario",
      description =
          "Reactiva una cuenta de usuario que ha sido previamente desactivada, utilizando su RUT.")
  @ApiResponse(
      responseCode = "200",
      description = "Usuario activado exitosamente.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "400",
      description = "El usuario ya se encuentra activo.",
      content = @Content())
  @ApiResponse(responseCode = "404", description = "Usuario no encontrado.", content = @Content())
  @PatchMapping("/{rut}/activate")
  public ResponseEntity<UserResponseDTO> activateUser(
      @Parameter(description = "RUT del usuario a activar", required = true) @PathVariable
          String rut) {
    log.info("Activando por RUT: {}", rut);
    return ResponseEntity.ok(userService.activateUserByRut(rut));
  }

  @Operation(
      summary = "Actualizar Rol de un Usuario",
      description =
          "Modifica el rol de un usuario específico. El rol debe ser uno de los valores permitidos en el sistema (ej. USER_APP, USER_ADMIN).")
  @ApiResponse(
      responseCode = "200",
      description = "Rol actualizado exitosamente.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "400",
      description = "El rol proporcionado no es válido.",
      content = @Content())
  @ApiResponse(
      responseCode = "404",
      description = "Usuario no encontrado o inactivo.",
      content = @Content())
  @PatchMapping("/{rut}/role")
  public ResponseEntity<UserResponseDTO> updateUserRole(
      @Parameter(description = "RUT del usuario cuyo rol se va a actualizar", required = true)
          @PathVariable
          String rut,
      @RequestBody UpdateUserRoleDTO roleDTO) {
    return ResponseEntity.ok(userService.updateUserRole(rut, roleDTO.getRole()));
  }

  @Operation(
      summary = "Actualizar Información de un Usuario",
      description =
          "Actualiza los datos de un usuario existente. Solo se modifican los campos proporcionados en el cuerpo de la solicitud. No se puede cambiar el RUT.")
  @ApiResponse(
      responseCode = "200",
      description = "Usuario actualizado exitosamente.",
      content =
          @Content(
              mediaType = "application/json",
              schema = @Schema(implementation = UserResponseDTO.class)))
  @ApiResponse(
      responseCode = "400",
      description = "Datos inválidos, como un email que ya está en uso.",
      content = @Content())
  @ApiResponse(
      responseCode = "404",
      description = "Usuario no encontrado o inactivo.",
      content = @Content())
  @PutMapping("/{rut}")
  public ResponseEntity<UserResponseDTO> updateUser(
      @Parameter(description = "RUT del usuario a actualizar", required = true) @PathVariable
          String rut,
      @Valid @RequestBody UserUpdateDTO userDTO) {
    log.info("Recibida solicitud de actualización para RUT: {}", rut);
    UserResponseDTO updatedUser = userService.updateUser(rut, userDTO);
    return ResponseEntity.ok(updatedUser);
  }
}
