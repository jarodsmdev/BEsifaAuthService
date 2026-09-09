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
import com.evecta.auth.util.TokenHashUtil;

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

        Token refreshToken = new Token();
        refreshToken.setTokenHash(TokenHashUtil.hashToken("raw-refresh-token-value"));
        refreshToken.setTokenType(Token.TokenType.REFRESH);
        refreshToken.setFamilyId("family-test");
        refreshToken.setRevoked(false);
        refreshToken.setExpired(false);
        refreshToken.setExpiresAt(LocalDateTime.now().plusDays(1));
        refreshToken.setUser(user);
        tokenRepository.save(refreshToken);
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
    @DisplayName("findByTokenHash con hash de refresh token lo encuentra")
    void findByTokenHash_hashExistente_retornaToken() {
        String hash = TokenHashUtil.hashToken("raw-refresh-token-value");
        var found = tokenRepository.findByTokenHash(hash);
        assertThat(found).isPresent();
        assertThat(found.get().getTokenType()).isEqualTo(Token.TokenType.REFRESH);
        // El texto plano NUNCA se persiste
        assertThat(found.get().getToken()).isNull();
    }

    @Test
    @DisplayName("findByTokenHash con hash inexistente retorna vacío")
    void findByTokenHash_hashInexistente_retornaVacio() {
        var found = tokenRepository.findByTokenHash("hash-inexistente");
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("findAllByFamilyId retorna los tokens de la familia")
    void findAllByFamilyId_retornaMiembros() {
        List<Token> familyTokens = tokenRepository.findAllByFamilyId("family-test");
        assertThat(familyTokens).hasSize(1);
        assertThat(familyTokens.get(0).getFamilyId()).isEqualTo("family-test");
    }

    @Test
    @DisplayName("findAllByUser_RutAndExpiredFalseAndRevokedFalse solo retorna tokens válidos")
    void findAllValidTokens_soloValidos() {
        // BEARER válido + REFRESH válido (sin revocar ni expirar)
        List<Token> tokens = tokenRepository.findAllByUser_RutAndExpiredFalseAndRevokedFalse("11111111");
        assertThat(tokens).hasSize(2);
        assertThat(tokens)
                .extracting(Token::getTokenType)
                .containsExactlyInAnyOrder(Token.TokenType.BEARER, Token.TokenType.REFRESH);
    }

    @Test
    @DisplayName("findAllByUser_Rut retorna todos los tokens del usuario")
    void findAllByUserRut_retornaTodos() {
        List<Token> tokens = tokenRepository.findAllByUser_Rut("11111111");
        assertThat(tokens).hasSize(4);
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
