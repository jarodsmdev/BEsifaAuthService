package com.evecta.auth.controller;

import com.evecta.auth.dto.user.UpdateUserRoleDTO;
import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.dto.user.UserResponseDTO;
import com.evecta.auth.dto.user.UserUpdateDTO;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.config.SecurityConfig;
import com.evecta.auth.repository.ITokenRepository;
import com.evecta.auth.service.JwtService;
import com.evecta.auth.service.UserService;
import com.evecta.auth.util.TestDataBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@Import(SecurityConfig.class)
@ActiveProfiles("test")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private ITokenRepository tokenRepository;

    private UserResponseDTO userResponseDTO() {
        return UserResponseDTO.builder()
                .rut("11111111")
                .dv("1")
                .name("Test")
                .lastName("User")
                .email("test@example.com")
                .role("USER_ADMIN")
                .isActive(true)
                .build();
    }

    @Test
    @WithMockUser(authorities = "USER_ADMIN")
    void registerUser_conAdmin_retorna201() throws Exception {
        UserCreateDTO request = TestDataBuilder.createUserCreateDTO();

        when(userService.createOrReactivateUser(any(UserCreateDTO.class), anyString()))
                .thenReturn(TestDataBuilder.createUserEntity(UserRole.USER_ADMIN, "test@example.com", "11111111", "1"));

        mockMvc.perform(post("/auth/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.rut").value("11111111"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    @Test
    @WithMockUser(authorities = "USER_APP")
    void registerUser_sinPermisos_retorna403() throws Exception {
        UserCreateDTO request = TestDataBuilder.createUserCreateDTO();

        mockMvc.perform(post("/auth/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "USER_ADMIN")
    void registerUser_conRutInvalido_retorna400() throws Exception {
        UserCreateDTO request = TestDataBuilder.createUserCreateDTO();

        when(userService.createOrReactivateUser(any(UserCreateDTO.class), anyString()))
                .thenThrow(new IllegalArgumentException("RUT inv\u00e1lido"));

        mockMvc.perform(post("/auth/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void getUserByRut_existente_retorna200() throws Exception {
        UserResponseDTO response = userResponseDTO();

        when(userService.findUserByRut("11111111")).thenReturn(response);

        mockMvc.perform(get("/auth/api/v1/users/11111111"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rut").value("11111111"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    @Test
    @WithMockUser
    void getUserByEmail_existente_retorna200() throws Exception {
        UserResponseDTO response = userResponseDTO();

        when(userService.findUserByEmail("test@example.com")).thenReturn(response);

        mockMvc.perform(get("/auth/api/v1/users/email/test@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rut").value("11111111"))
                .andExpect(jsonPath("$.email").value("test@example.com"));
    }

    @Test
    @WithMockUser
    void getAllUsers_retornaPagina200() throws Exception {
        Page<UserResponseDTO> page = new PageImpl<>(List.of(userResponseDTO()));

        when(userService.findAllUsers(any(), any())).thenReturn(page);

        mockMvc.perform(get("/auth/api/v1/users")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content[0].rut").value("11111111"));
    }

    @Test
    @WithMockUser
    void getAllFiscalizadores_retornaLista200() throws Exception {
        List<UserResponseDTO> users = List.of(userResponseDTO());

        when(userService.findAllFiscalizadores()).thenReturn(users);

        mockMvc.perform(get("/auth/api/v1/users/fiscalizadores"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].rut").value("11111111"));
    }

    @Test
    @WithMockUser(authorities = "USER_ADMIN")
    void deactivateUser_conAdmin_retorna200() throws Exception {
        UserResponseDTO response = userResponseDTO();

        when(userService.deactivateUserByRut(anyString(), anyString())).thenReturn(response);

        mockMvc.perform(delete("/auth/api/v1/users")
                        .param("rut", "11111111"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rut").value("11111111"));
    }

    @Test
    @WithMockUser(authorities = "USER_ADMIN")
    void activateUser_conAdmin_retorna200() throws Exception {
        UserResponseDTO response = userResponseDTO();

        when(userService.activateUserByRut(anyString(), anyString())).thenReturn(response);

        mockMvc.perform(patch("/auth/api/v1/users/11111111/activate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rut").value("11111111"));
    }

    @Test
    @WithMockUser(authorities = "USER_ADMIN")
    void updateUserRole_conAdmin_retorna200() throws Exception {
        UpdateUserRoleDTO roleDTO = new UpdateUserRoleDTO();
        roleDTO.setRole("USER_ADMIN");
        UserResponseDTO response = userResponseDTO();

        when(userService.updateUserRole(anyString(), anyString(), anyString())).thenReturn(response);

        mockMvc.perform(patch("/auth/api/v1/users/11111111/role")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(roleDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rut").value("11111111"));
    }

    @Test
    @WithMockUser
    void updateUser_conDatosValidos_retorna200() throws Exception {
        UserUpdateDTO updateDTO = UserUpdateDTO.builder()
                .name("Updated")
                .lastName("User")
                .email("updated@example.com")
                .build();
        UserResponseDTO response = UserResponseDTO.builder()
                .rut("11111111")
                .dv("1")
                .name("Updated")
                .lastName("User")
                .email("updated@example.com")
                .role("USER_ADMIN")
                .isActive(true)
                .build();

        when(userService.updateUser(anyString(), any(UserUpdateDTO.class), anyString())).thenReturn(response);

        mockMvc.perform(put("/auth/api/v1/users/11111111")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated"))
                .andExpect(jsonPath("$.email").value("updated@example.com"));
    }
}
