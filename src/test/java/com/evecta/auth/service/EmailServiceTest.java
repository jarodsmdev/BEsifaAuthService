package com.evecta.auth.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @InjectMocks
    private EmailService emailService;

    @Captor
    private ArgumentCaptor<SimpleMailMessage> messageCaptor;

    private static final String FROM = "noreply@sifa.cl";
    private static final String TO = "user@example.com";
    private static final String CODE = "123456";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(emailService, "fromEmail", FROM);
    }

    @Test
    void sendRecoveryCode_enviaEmail() {
        emailService.sendRecoveryCode(TO, CODE);

        verify(mailSender).send(messageCaptor.capture());
        SimpleMailMessage sent = messageCaptor.getValue();

        assertEquals(FROM, sent.getFrom());
        assertEquals(TO, sent.getTo()[0]);
        assertEquals("Código de Recuperación de Contraseña - SIFA", sent.getSubject());
        assertTrue(sent.getText().contains(CODE));
    }
}
