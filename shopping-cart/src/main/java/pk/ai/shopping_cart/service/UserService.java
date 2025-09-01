package pk.ai.shopping_cart.service;

import pk.ai.shopping_cart.dto.auth.AuthenticationResponse;
import pk.ai.shopping_cart.dto.user.UserLoginRequest;
import pk.ai.shopping_cart.dto.user.UserRegistrationRequest;
import pk.ai.shopping_cart.dto.user.UserResponse;
import pk.ai.shopping_cart.entity.User;

/**
 * User service interface for user management operations
 */
public interface UserService {

    /**
     * Register a new user
     */
    UserResponse registerUser(UserRegistrationRequest request);

    /**
     * Authenticate user and return JWT token
     */
    AuthenticationResponse authenticateUser(UserLoginRequest request);

    /**
     * Logout user by invalidating JWT token
     */
    void logoutUser(String token);

    /**
     * Get user by ID
     */
    UserResponse getUserById(String userId);

    /**
     * Get user by username
     */
    UserResponse getUserByUsername(String username);

    /**
     * Get user by email
     */
    UserResponse getUserByEmail(String email);

    /**
     * Update user profile
     */
    UserResponse updateUserProfile(String userId, UserResponse userUpdate);

    /**
     * Check if username is available
     */
    boolean isUsernameAvailable(String username);

    /**
     * Check if email is available
     */
    boolean isEmailAvailable(String email);

    /**
     * Convert User entity to UserResponse DTO
     */
    UserResponse convertToUserResponse(User user);
}
