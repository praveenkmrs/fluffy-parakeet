package pk.ai.shopping_cart.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

/**
 * User entity for MongoDB storage
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users")
public class User {

    @Id
    private String id;

    @Indexed(unique = true)
    private String email;

    @Indexed(unique = true)
    private String username;

    private String passwordHash;

    private String firstName;
    private String lastName;
    private String phoneNumber;

    private UserStatus status;
    private Set<UserRole> roles;

    private Profile profile;
    private List<Address> addresses;

    private LocalDateTime createdAt;
    private LocalDateTime lastUpdatedAt;
    private LocalDateTime lastLoginAt;

    private boolean emailVerified;
    private boolean phoneVerified;
    private boolean twoFactorEnabled;

    public enum UserStatus {
        ACTIVE,
        INACTIVE,
        SUSPENDED,
        PENDING_VERIFICATION
    }

    public enum UserRole {
        USER,
        ADMIN,
        MODERATOR
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Profile {
        private String dateOfBirth;
        private String gender;
        private String preferredLanguage;
        private String timezone;
        private String avatarUrl;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Address {
        private String id;
        private String type; // HOME, WORK, BILLING, SHIPPING
        private String street;
        private String city;
        private String state;
        private String postalCode;
        private String country;
        private boolean isDefault;
    }
}
