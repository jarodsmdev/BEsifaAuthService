package com.evecta.auth.config;

import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;
import com.evecta.auth.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class DataInitializer {
    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
    private final IUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.email}")
    private String adminEmail;

    @Value("${app.admin.password}")
    private String adminPassword;

    @Bean
    @SuppressWarnings("null")
    CommandLineRunner initAdminUser() {
        return args -> {
            UserEntity existingAdmin = userRepository.findByRut("11111111").orElse(null);
            if (existingAdmin != null) {
                if (!existingAdmin.getEmail().equals(adminEmail)) {
                    log.info("[!] Actualizando correo del admin a: {}", adminEmail);
                    existingAdmin.setEmail(adminEmail);
                    userRepository.save(existingAdmin);
                } else {
                    log.info("[!] Usuario admin ya existe con correo: {}", adminEmail);
                }
                return;
            }

            UserEntity admin = UserEntity.builder()
                    .rut("11111111")
                    .dv("1")
                    .name("USER ADMIN")
                    .lastName("ROOT")
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .role(UserRole.USER_ADMIN)
                    .isActive(true)
                    .build();

            userRepository.save(admin);
            log.info("[+] Usuario admin creado con email: {}", adminEmail);
        };
    }
}
