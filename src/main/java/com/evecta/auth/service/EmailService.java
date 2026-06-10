package com.evecta.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:}")
    private String fromEmail;

    public void sendRecoveryCode(String to, String code) {
        log.info("Intentando enviar correo de recuperación a: {}", to);
        
        if (fromEmail == null || fromEmail.trim().isEmpty()) {
            log.error("No se puede enviar el correo: spring.mail.username no está configurado en application.properties");
            throw new IllegalArgumentException("El servidor de correo no está configurado. Por favor, configure spring.mail.username en application.properties.");
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Código de Recuperación de Contraseña - SIFA");
            message.setText("Hola,\n\n"
                    + "Has solicitado restablecer tu contraseña en el sistema SIFA.\n\n"
                    + "Tu código de verificación de 6 dígitos es: " + code + "\n\n"
                    + "Este código expira en 15 minutos y se bloqueará después de 3 intentos fallidos.\n\n"
                    + "Si no solicitaste este cambio, puedes ignorar este correo.");
            
            mailSender.send(message);
            log.info("Correo enviado exitosamente a {}", to);
        } catch (MailException e) {
            log.error("Error al enviar correo SMTP a {}: {}", to, e.getMessage(), e);
            throw new IllegalArgumentException("Error al enviar el correo. Verifique la contraseña de aplicación o configuraciones de SMTP: " + e.getMessage());
        }
    }
}
