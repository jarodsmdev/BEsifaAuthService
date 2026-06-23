package com.evecta.auth.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    @DisplayName("IllegalArgumentException retorna 400 con mensaje de error")
    void illegalArgument_retorna400() {
        var response = handler.handleIllegalArgumentException(
                new IllegalArgumentException("Mensaje de error"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isEqualTo(Map.of("error", "Mensaje de error"));
    }

    @Test
    @DisplayName("IllegalStateException retorna 409 CONFLICT con mensaje de error")
    void illegalState_retorna409() {
        var response = handler.handleIllegalStateException(
                new IllegalStateException("Estado inválido"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isEqualTo(Map.of("error", "Estado inválido"));
    }

    @Test
    @DisplayName("MethodArgumentNotValidException retorna 400 con errores de campo")
    void validationException_retorna400_conErrores() {
        var ex = mock(MethodArgumentNotValidException.class);
        var bindingResult = mock(BindingResult.class);

        var fieldError1 = new FieldError("object", "email", "El email no puede estar vacío");
        var fieldError2 = new FieldError("object", "password", "La contraseña es obligatoria");

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getAllErrors()).thenReturn(List.of(fieldError1, fieldError2));

        var response = handler.handleValidationExceptions(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("email", "El email no puede estar vacío");
        assertThat(response.getBody()).containsEntry("password", "La contraseña es obligatoria");
    }

    @Test
    @DisplayName("BadCredentialsException retorna 401 con mensaje de error")
    void badCredentials_retorna401() {
        var response = handler.handleBadCredentialsException(
                new BadCredentialsException("Credenciales inválidas"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isEqualTo(Map.of("error", "Credenciales inválidas"));
    }
}
