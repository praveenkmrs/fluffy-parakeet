package pk.ai.shopping_cart.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.service.TokenBlacklistService;
import pk.ai.shopping_cart.util.JwtTokenUtil;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of TokenBlacklistService using in-memory storage
 * In production, consider using Redis or database for distributed systems
 */
@Slf4j
@Service
public class TokenBlacklistServiceImpl implements TokenBlacklistService {

    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    private final JwtTokenUtil jwtTokenUtil;

    public TokenBlacklistServiceImpl(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    public void blacklistToken(String token) {
        if (token != null && !token.trim().isEmpty()) {
            blacklistedTokens.add(token);
            log.info("Token added to blacklist. Total blacklisted tokens: {}", blacklistedTokens.size());
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        return token != null && blacklistedTokens.contains(token);
    }

    @Override
    @Scheduled(fixedRate = 3600000) // Run every hour
    public void cleanupExpiredTokens() {
        log.info("Starting cleanup of expired tokens from blacklist");
        int initialSize = blacklistedTokens.size();

        blacklistedTokens.removeIf(token -> {
            try {
                return jwtTokenUtil.isTokenExpired(token);
            } catch (Exception e) {
                // If token is invalid/malformed, remove it from blacklist
                log.debug("Removing invalid token from blacklist: {}", e.getMessage());
                return true;
            }
        });

        int removedCount = initialSize - blacklistedTokens.size();
        if (removedCount > 0) {
            log.info("Cleaned up {} expired tokens from blacklist. Remaining: {}",
                    removedCount, blacklistedTokens.size());
        }
    }

    /**
     * Get current blacklist size (for monitoring/debugging)
     */
    public int getBlacklistSize() {
        return blacklistedTokens.size();
    }
}
