package com.evecta.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import com.evecta.auth.model.Token;
import com.evecta.auth.model.UserEntity;
import com.evecta.auth.model.UserRole;

@DataJpaTest
@DisplayName("ITokenRepository")
class ITokenRepositoryTest {

    @Autowired
    private ITokenRepository tokenRepository;

    @Autowired
    private IUserRepository userRepository;

    private UserEntity user;
    private Token validToken;
    private Token revokedToken;
    private Token expiredToken;

    @BeforeEach
    void setUp() {
        user = new UserEntity();
        user.setRut("11111111");
        user.setDv("1");
        user.setName("Test");
        user.setLastName("User");
        user.setEmail("test@test.com");
        user.setPassword("$2a$10$hash");
        user.setRole(UserRole.USER_ADMIN);
        user.setActive(true);
        user = userRepository.save(user);

        validToken = new Token();
        validToken.setToken("valid-token-123");
        validToken.setTokenType(Token.TokenType.BEARER);
        validToken.setRevoked(false);
        validToken.setExpired(false);
        validToken.setExpiresAt(LocalDateTime.now().plusDays(1));
        validToken.setUser(user);
        validToken = tokenRepository.save(validToken);

        revokedToken = new Token();
        revokedToken.setToken("revoked-token-456");
        revokedToken.setTokenType(Token.TokenType.BEARER);
        revokedToken.setRevoked(true);
        revokedToken.setExpired(false);
        revokedToken.setExpiresAt(LocalDateTime.now().plusDays(1));
        revokedToken.setUser(user);
        tokenRepository.save(revokedToken);

        expiredToken = new Token();
        expiredToken.setToken("expired-token-789");
        expiredToken.setTokenType(Token.TokenType.BEARER);
        expiredToken.setRevoked(false);
        expiredToken.setExpired(true);
        expiredToken.setExpiresAt(LocalDateTime.now().minusDays(1));
        expiredToken.setUser(user);
        tokenRepository.save(expiredToken);
    }

    @Test
    @DisplayName("findByToken con token existente lo encuentra")
    void findByToken_tokenExistente_retornaToken() {
        var found = tokenRepository.findByToken("valid-token-123");
        assertThat(found).isPresent();
    }

    @Test
    @DisplayName("findByToken con token inexistente retorna vacío")
    void findByToken_tokenInexistente_retornaVacio() {
        var found = tokenRepository.findByToken("non-existent");
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("findAllByUser_RutAndExpiredFalseAndRevokedFalse solo retorna tokens válidos")
    void findAllValidTokens_soloValidos() {
        List<Token> tokens = tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse("11111111");
        assertThat(tokens).hasSize(1);
        assertThat(tokens.get(0).getToken()).isEqualTo("valid-token-123");
    }

    @Test
    @DisplayName("findAllByUser_Rut retorna todos los tokens del usuario")
    void findAllByUserRut_retornaTodos() {
        List<Token> tokens = tokenRepository.findAllByUser_Rut("11111111");
        assertThat(tokens).hasSize(3);
    }

    @Test
    @DisplayName("findAllByOrderByIdTokenDesc retorna tokens ordenados")
    void findAllOrdered_ordenDescendente() {
        var page = tokenRepository.findAllByOrderByIdTokenDesc(PageRequest.of(0, 10));
        assertThat(page.getContent()).isNotEmpty();
        List<Long> ids = page.getContent().stream().map(Token::getIdToken).toList();
        assertThat(ids).isSortedAccordingTo((a, b) -> Long.compare(b, a));
    }
}
