package pk.ai.shopping_cart.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pk.ai.shopping_cart.dto.user.UserResponse;

/**
 * Authentication response DTO containing JWT token and user info
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    private String accessToken;

    @Builder.Default
    private String tokenType = "Bearer";

    private long expiresIn; // seconds
    private UserResponse user;

    public AuthenticationResponse(String accessToken, long expiresIn, UserResponse user) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.user = user;
    }
}
