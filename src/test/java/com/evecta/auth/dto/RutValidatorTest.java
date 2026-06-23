package com.evecta.auth.dto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RutValidator")
class RutValidatorTest {

    @Test
    @DisplayName("validarRut con RUT 11111111-1 válido retorna true")
    void validarRut_rutValido_retornaTrue() {
        assertThat(RutValidator.validarRut("11111111", "1")).isTrue();
    }

    @Test
    @DisplayName("validarRut con RUT 12345678-0 inválido retorna false")
    void validarRut_rutInvalido_retornaFalse() {
        assertThat(RutValidator.validarRut("12345678", "0")).isFalse();
    }

    @Test
    @DisplayName("validarRut con RUT corto retorna false")
    void validarRut_rutCorto_retornaFalse() {
        assertThat(RutValidator.validarRut("123", "1")).isFalse();
    }

    @Test
    @DisplayName("validarRut con RUT sin dígito verificador retorna false")
    void validarRut_sinDigito_retornaFalse() {
        assertThat(RutValidator.validarRut(null, "1")).isFalse();
    }

    @Test
    @DisplayName("validarRut con DV K mayúscula retorna true para 11111112-K")
    void validarRut_dvKMayuscula_retornaTrue() {
        assertThat(RutValidator.validarRut("11111112", "K")).isTrue();
    }
}
