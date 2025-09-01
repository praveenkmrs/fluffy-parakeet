package pk.ai.shopping_cart.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.dto.auth.AuthenticationResponse;
import pk.ai.shopping_cart.dto.user.UserLoginRequest;
import pk.ai.shopping_cart.dto.user.UserRegistrationRequest;
import pk.ai.shopping_cart.dto.user.UserResponse;
import pk.ai.shopping_cart.entity.User;
import pk.ai.shopping_cart.repository.UserRepository;
import pk.ai.shopping_cart.service.UserService;
import pk.ai.shopping_cart.service.TokenBlacklistService;
import pk.ai.shopping_cart.util.JwtTokenUtil;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * User service implementation
 */
@Slf4j
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final TokenBlacklistService tokenBlacklistService;

    public UserServiceImpl(UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenUtil jwtTokenUtil,
            TokenBlacklistService tokenBlacklistService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenUtil = jwtTokenUtil;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    public UserResponse registerUser(UserRegistrationRequest request) {
        log.info("Registering new user with username: {}", request.getUsername());

        // Check if username already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists: " + request.getUsername());
        }

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists: " + request.getEmail());
        }

        // Create new user
        Set<User.UserRole> roles = new HashSet<>();
        roles.add(User.UserRole.USER);

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .status(User.UserStatus.PENDING_VERIFICATION)
                .roles(roles)
                .emailVerified(false)
                .phoneVerified(false)
                .twoFactorEnabled(false)
                .createdAt(LocalDateTime.now())
                .lastUpdatedAt(LocalDateTime.now())
                .build();

        // Save user
        User savedUser = userRepository.save(user);
        log.info("User registered successfully with ID: {}", savedUser.getId());

        return convertToUserResponse(savedUser);
    }

    @Override
    public AuthenticationResponse authenticateUser(UserLoginRequest request) {
        log.info("Authenticating user: {}", request.getUsernameOrEmail());

        // Find user by username or email
        User user = userRepository.findByUsernameOrEmail(
                request.getUsernameOrEmail(),
                request.getUsernameOrEmail())
                .orElseThrow(() -> new RuntimeException("User not found: " + request.getUsernameOrEmail()));

        // Check password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        // Check if user is active
        if (user.getStatus() != User.UserStatus.ACTIVE && user.getStatus() != User.UserStatus.PENDING_VERIFICATION) {
            throw new RuntimeException("User account is not active");
        }

        // Update last login time
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate JWT token with user information and claims
        String token = jwtTokenUtil.generateTokenWithClaims(user);

        log.info("User authenticated successfully: {}", user.getUsername());

        return AuthenticationResponse.builder()
                .accessToken(token)
                .expiresIn(jwtTokenUtil.getExpirationSeconds())
                .user(convertToUserResponse(user))
                .build();
    }

    @Override
    public void logoutUser(String token) {
        log.info("Logging out user - invalidating token");

        if (token == null || token.trim().isEmpty()) {
            throw new RuntimeException("Token cannot be null or empty");
        }

        // Add token to blacklist
        tokenBlacklistService.blacklistToken(token);

        log.info("User logged out successfully - token blacklisted");
    }

    @Override
    public UserResponse getUserById(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        return convertToUserResponse(user);
    }

    @Override
    public UserResponse getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found with username: " + username));
        return convertToUserResponse(user);
    }

    @Override
    public UserResponse getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        return convertToUserResponse(user);
    }

    @Override
    public UserResponse updateUserProfile(String userId, UserResponse userUpdate) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        // Update fields
        if (userUpdate.getFirstName() != null) {
            user.setFirstName(userUpdate.getFirstName());
        }
        if (userUpdate.getLastName() != null) {
            user.setLastName(userUpdate.getLastName());
        }
        if (userUpdate.getPhoneNumber() != null) {
            user.setPhoneNumber(userUpdate.getPhoneNumber());
        }

        user.setLastUpdatedAt(LocalDateTime.now());

        User savedUser = userRepository.save(user);
        return convertToUserResponse(savedUser);
    }

    @Override
    public boolean isUsernameAvailable(String username) {
        return !userRepository.existsByUsername(username);
    }

    @Override
    public boolean isEmailAvailable(String email) {
        return !userRepository.existsByEmail(email);
    }

    @Override
    public UserResponse convertToUserResponse(User user) {
        UserResponse.UserResponseBuilder builder = UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .status(user.getStatus())
                .roles(user.getRoles())
                .emailVerified(user.isEmailVerified())
                .phoneVerified(user.isPhoneVerified())
                .twoFactorEnabled(user.isTwoFactorEnabled())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt());

        // Add profile information if available
        if (user.getProfile() != null) {
            builder.preferredLanguage(user.getProfile().getPreferredLanguage())
                    .timezone(user.getProfile().getTimezone())
                    .avatarUrl(user.getProfile().getAvatarUrl());
        }

        return builder.build();
    }
}
