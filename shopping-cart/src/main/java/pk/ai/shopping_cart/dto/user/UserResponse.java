package pk.ai.shopping_cart.dto.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pk.ai.shopping_cart.entity.User;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * User response DTO for API responses
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {

    private String id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;

    private User.UserStatus status;
    private Set<User.UserRole> roles;

    private boolean emailVerified;
    private boolean phoneVerified;
    private boolean twoFactorEnabled;

    private LocalDateTime createdAt;
    private LocalDateTime lastLoginAt;

    // Profile information
    private String preferredLanguage;
    private String timezone;
    private String avatarUrl;
}
