package com.evecta.auth.dto;

import static org.assertj.core.api.Assertions.assertThat;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.evecta.auth.dto.auth.LoginRequestDTO;
import jakarta.validation.ConstraintViolation;

@DisplayName("LoginRequestDTO Validation")
class LoginRequestDTOValidationTest {

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
        var dto = new LoginRequestDTO("test@example.com", "TestPass123");
        Set<ConstraintViolation<LoginRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("Email vacío genera error")
    void emailVacio_errorValidacion() {
        var dto = new LoginRequestDTO("", "TestPass123");
        Set<ConstraintViolation<LoginRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("Password vacío genera error")
    void passwordVacio_errorValidacion() {
        var dto = new LoginRequestDTO("test@example.com", "");
        Set<ConstraintViolation<LoginRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }
}
