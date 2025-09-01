package pk.ai.shopping_cart.service;

/**
 * Service interface for managing blacklisted JWT tokens
 */
public interface TokenBlacklistService {

    /**
     * Add a token to the blacklist
     * 
     * @param token The JWT token to blacklist
     */
    void blacklistToken(String token);

    /**
     * Check if a token is blacklisted
     * 
     * @param token The JWT token to check
     * @return true if token is blacklisted, false otherwise
     */
    boolean isTokenBlacklisted(String token);

    /**
     * Remove expired tokens from blacklist (cleanup)
     */
    void cleanupExpiredTokens();
}
