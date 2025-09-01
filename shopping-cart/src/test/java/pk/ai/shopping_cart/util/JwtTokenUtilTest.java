package pk.ai.shopping_cart.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for JwtTokenUtil
 */
@ActiveProfiles("test")
@DisplayName("JwtTokenUtil Unit Tests")
class JwtTokenUtilTest {

    private JwtTokenUtil jwtTokenUtil;

    @BeforeEach
    void setUp() {
        jwtTokenUtil = new JwtTokenUtil();
        // Set test values using reflection since they're normally injected
        ReflectionTestUtils.setField(jwtTokenUtil, "secret",
                "my-very-secure-secret-key-for-jwt-token-signing-that-is-at-least-512-bits-long-and-should-work-with-hs512-algorithm");
        ReflectionTestUtils.setField(jwtTokenUtil, "jwtExpiration", 3600000L); // 1 hour
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Should generate token for valid username")
        void shouldGenerateTokenForValidUsername() {
            // Given
            String username = "testuser";

            // When
            String token = jwtTokenUtil.generateToken(username);

            // Then
            assertThat(token).isNotNull();
            assertThat(token).isNotEmpty();
            assertThat(token.split("\\.")).hasSize(3); // JWT has 3 parts separated by dots
        }

        @Test
        @DisplayName("Should generate different tokens for different usernames")
        void shouldGenerateDifferentTokensForDifferentUsernames() {
            // Given
            String username1 = "user1";
            String username2 = "user2";

            // When
            String token1 = jwtTokenUtil.generateToken(username1);
            String token2 = jwtTokenUtil.generateToken(username2);

            // Then
            assertThat(token1).isNotEqualTo(token2);
        }

        @Test
        @DisplayName("Should handle null username gracefully")
        void shouldHandleNullUsernameGracefully() {
            // When
            String token = jwtTokenUtil.generateToken(null);

            // Then
            assertThat(token).isNotNull();
            assertThat(token).isNotEmpty();
            assertThat(jwtTokenUtil.getUsernameFromToken(token)).isNull(); // JWT library returns null for null subject
        }

        @Test
        @DisplayName("Should handle empty username gracefully")
        void shouldHandleEmptyUsernameGracefully() {
            // Given
            String emptyUsername = "";

            // When
            String token = jwtTokenUtil.generateToken(emptyUsername);

            // Then
            assertThat(token).isNotNull();
            assertThat(token).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should validate token successfully with correct username")
        void shouldValidateTokenSuccessfullyWithCorrectUsername() {
            // Given
            String username = "testuser";
            String token = jwtTokenUtil.generateToken(username);

            // When
            Boolean isValid = jwtTokenUtil.validateToken(token, username);

            // Then
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should reject token with incorrect username")
        void shouldRejectTokenWithIncorrectUsername() {
            // Given
            String originalUsername = "testuser";
            String differentUsername = "otheruser";
            String token = jwtTokenUtil.generateToken(originalUsername);

            // When
            Boolean isValid = jwtTokenUtil.validateToken(token, differentUsername);

            // Then
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should reject malformed token")
        void shouldRejectMalformedToken() {
            // Given
            String malformedToken = "invalid.token.format";
            String username = "testuser";

            // When & Then
            assertThatThrownBy(() -> jwtTokenUtil.validateToken(malformedToken, username))
                    .isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("Should reject null token")
        void shouldRejectNullToken() {
            // Given
            String username = "testuser";

            // When & Then
            assertThatThrownBy(() -> jwtTokenUtil.validateToken(null, username))
                    .isInstanceOf(RuntimeException.class);
        }
    }

    @Nested
    @DisplayName("Token Information Extraction Tests")
    class TokenExtractionTests {

        @Test
        @DisplayName("Should extract username from token correctly")
        void shouldExtractUsernameFromTokenCorrectly() {
            // Given
            String username = "testuser";
            String token = jwtTokenUtil.generateToken(username);

            // When
            String extractedUsername = jwtTokenUtil.getUsernameFromToken(token);

            // Then
            assertThat(extractedUsername).isEqualTo(username);
        }

        @Test
        @DisplayName("Should extract expiration date from token")
        void shouldExtractExpirationDateFromToken() {
            // Given
            String username = "testuser";
            String token = jwtTokenUtil.generateToken(username);

            // When
            var expirationDate = jwtTokenUtil.getExpirationDateFromToken(token);

            // Then
            assertThat(expirationDate).isNotNull();
            assertThat(expirationDate).isAfter(new java.util.Date());
        }

        @Test
        @DisplayName("Should determine token is not expired for fresh token")
        void shouldDetermineTokenIsNotExpiredForFreshToken() {
            // Given
            String username = "testuser";
            String token = jwtTokenUtil.generateToken(username);

            // When
            Boolean isExpired = jwtTokenUtil.isTokenExpired(token);

            // Then
            assertThat(isExpired).isFalse();
        }

        @Test
        @DisplayName("Should handle token extraction errors gracefully")
        void shouldHandleTokenExtractionErrorsGracefully() {
            // Given
            String invalidToken = "invalid.token";

            // When & Then
            assertThatThrownBy(() -> jwtTokenUtil.getUsernameFromToken(invalidToken))
                    .isInstanceOf(RuntimeException.class);
        }
    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should return correct expiration seconds")
        void shouldReturnCorrectExpirationSeconds() {
            // When
            long expirationSeconds = jwtTokenUtil.getExpirationSeconds();

            // Then
            assertThat(expirationSeconds).isEqualTo(3600L); // 1 hour
        }

        @Test
        @DisplayName("Should generate different tokens at different times")
        void shouldGenerateDifferentTokensAtDifferentTimes() {
            // Given
            String username = "testuser";

            // When
            String token1 = jwtTokenUtil.generateToken(username);
            // Wait enough time to ensure different timestamps (JWT uses seconds precision)
            try {
                Thread.sleep(1100); // Wait more than 1 second to ensure different iat
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            String token2 = jwtTokenUtil.generateToken(username);

            // Then
            // Tokens should be different due to different issued-at timestamps
            assertThat(token1).isNotEqualTo(token2);

            // But both should be valid for the same username
            assertThat(jwtTokenUtil.validateToken(token1, username)).isTrue();
            assertThat(jwtTokenUtil.validateToken(token2, username)).isTrue();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle very long username")
        void shouldHandleVeryLongUsername() {
            // Given
            String longUsername = "a".repeat(1000);

            // When
            String token = jwtTokenUtil.generateToken(longUsername);

            // Then
            assertThat(token).isNotNull();
            assertThat(jwtTokenUtil.getUsernameFromToken(token)).isEqualTo(longUsername);
        }

        @Test
        @DisplayName("Should handle username with special characters")
        void shouldHandleUsernameWithSpecialCharacters() {
            // Given
            String specialUsername = "user@domain.com!#$%";

            // When
            String token = jwtTokenUtil.generateToken(specialUsername);

            // Then
            assertThat(token).isNotNull();
            assertThat(jwtTokenUtil.getUsernameFromToken(token)).isEqualTo(specialUsername);
        }

        @Test
        @DisplayName("Should handle unicode username")
        void shouldHandleUnicodeUsername() {
            // Given
            String unicodeUsername = "用户名测试";

            // When
            String token = jwtTokenUtil.generateToken(unicodeUsername);

            // Then
            assertThat(token).isNotNull();
            assertThat(jwtTokenUtil.getUsernameFromToken(token)).isEqualTo(unicodeUsername);
        }
    }
}
