package pk.ai.shopping_cart.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import pk.ai.shopping_cart.entity.User;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * JWT utility class for token generation and validation
 */
@Slf4j
@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    /**
     * Generate JWT token for username (backward compatibility)
     */
    public String generateToken(String username) {
        return createToken(username, new HashMap<>());
    }

    /**
     * Generate JWT token with user information and claims
     */
    public String generateTokenWithClaims(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("email", user.getEmail());
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());
        claims.put("status", user.getStatus().toString());
        claims.put("emailVerified", user.isEmailVerified());

        // Add roles as a list of strings
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            claims.put("roles", user.getRoles().stream()
                    .map(role -> role.toString())
                    .collect(Collectors.toList()));
        }

        // Add phone if available
        if (user.getPhoneNumber() != null) {
            claims.put("phoneNumber", user.getPhoneNumber());
        }

        return createToken(user.getUsername(), claims);
    }

    /**
     * Create JWT token with custom claims
     */
    private String createToken(String subject, Map<String, Object> claims) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Extract username from token
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Extract user ID from token
     */
    public String getUserIdFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("userId", String.class));
    }

    /**
     * Extract email from token
     */
    public String getEmailFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("email", String.class));
    }

    /**
     * Extract roles from token
     */
    @SuppressWarnings("unchecked")
    public java.util.List<String> getRolesFromToken(String token) {
        return getClaimFromToken(token, claims -> (java.util.List<String>) claims.get("roles"));
    }

    /**
     * Extract user status from token
     */
    public String getUserStatusFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("status", String.class));
    }

    /**
     * Extract email verification status from token
     */
    public Boolean getEmailVerifiedFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("emailVerified", Boolean.class));
    }

    /**
     * Extract expiration date from token
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Extract claim from token
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Get all claims from token
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Check if token is expired
     */
    public Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /**
     * Validate token
     */
    public Boolean validateToken(String token, String username) {
        final String tokenUsername = getUsernameFromToken(token);
        return (tokenUsername.equals(username) && !isTokenExpired(token));
    }

    /**
     * Get token expiration in seconds
     */
    public long getExpirationSeconds() {
        return jwtExpiration / 1000;
    }
}
