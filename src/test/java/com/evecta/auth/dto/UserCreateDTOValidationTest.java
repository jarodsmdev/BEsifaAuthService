package com.evecta.auth.dto;

import static org.assertj.core.api.Assertions.assertThat;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.evecta.auth.dto.user.UserCreateDTO;
import com.evecta.auth.model.UserRole;
import jakarta.validation.ConstraintViolation;

@DisplayName("UserCreateDTO Validation")
class UserCreateDTOValidationTest {

    private static Validator validator;

    @BeforeAll
    static void setUp() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    @Test
    @DisplayName("DTO con datos válidos no tiene errores")
    void datosValidos_sinErrores() {
        var dto = new UserCreateDTO();
        dto.setRut("11111111");
        dto.setDv("1");
        dto.setName("Test");
        dto.setLastName("User");
        dto.setEmail("test@example.com");
        dto.setRole(UserRole.USER_ADMIN);
        dto.setPassword("TestPass123");

        Set<ConstraintViolation<UserCreateDTO>> violations = validator.validate(dto);
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("RUT inválido genera error de validación")
    void rutInvalido_errorValidacion() {
        var dto = new UserCreateDTO();
        dto.setRut("12345678");
        dto.setDv("0");
        dto.setName("Test");
        dto.setLastName("User");
        dto.setEmail("test@example.com");
        dto.setRole(UserRole.USER_ADMIN);
        dto.setPassword("TestPass123");

        Set<ConstraintViolation<UserCreateDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("Email inválido genera error")
    void emailInvalido_errorValidacion() {
        var dto = new UserCreateDTO();
        dto.setRut("11111111");
        dto.setDv("1");
        dto.setName("Test");
        dto.setLastName("User");
        dto.setEmail("email-invalido");
        dto.setRole(UserRole.USER_ADMIN);
        dto.setPassword("TestPass123");

        Set<ConstraintViolation<UserCreateDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("Password sin requisitos genera error")
    void passwordSinRequisitos_errorValidacion() {
        var dto = new UserCreateDTO();
        dto.setRut("11111111");
        dto.setDv("1");
        dto.setName("Test");
        dto.setLastName("User");
        dto.setEmail("test@example.com");
        dto.setRole(UserRole.USER_ADMIN);
        dto.setPassword("solo");

        Set<ConstraintViolation<UserCreateDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }
}
