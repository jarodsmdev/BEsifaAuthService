package com.evecta.auth.dto;

import static org.assertj.core.api.Assertions.assertThat;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.evecta.auth.dto.auth.ChangePasswordRequestDTO;
import jakarta.validation.ConstraintViolation;

@DisplayName("ChangePasswordRequestDTO Validation")
class ChangePasswordRequestDTOValidationTest {

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
        var dto = new ChangePasswordRequestDTO("Secreta123", "NuevaClave456");
        Set<ConstraintViolation<ChangePasswordRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("OldPassword vacío genera error")
    void oldPasswordVacio_errorValidacion() {
        var dto = new ChangePasswordRequestDTO("", "NuevaClave456");
        Set<ConstraintViolation<ChangePasswordRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("NewPassword vacío genera error")
    void newPasswordVacio_errorValidacion() {
        var dto = new ChangePasswordRequestDTO("Secreta123", "");
        Set<ConstraintViolation<ChangePasswordRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("NewPassword sin mayúscula genera error")
    void newPasswordSinMayuscula_errorValidacion() {
        var dto = new ChangePasswordRequestDTO("Secreta123", "solonumeros123");
        Set<ConstraintViolation<ChangePasswordRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("NewPassword sin número genera error")
    void newPasswordSinNumero_errorValidacion() {
        var dto = new ChangePasswordRequestDTO("Secreta123", "SoloLetras");
        Set<ConstraintViolation<ChangePasswordRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }

    @Test
    @DisplayName("NewPassword demasiado corta genera error")
    void newPasswordCorta_errorValidacion() {
        var dto = new ChangePasswordRequestDTO("Secreta123", "Ab1");
        Set<ConstraintViolation<ChangePasswordRequestDTO>> violations = validator.validate(dto);
        assertThat(violations).isNotEmpty();
    }
}
