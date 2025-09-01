This file is a merged representation of the entire codebase, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
.mvn/
  wrapper/
    maven-wrapper.properties
src/
  main/
    java/
      pk/
        ai/
          shopping_cart/
            config/
              JwtAuthenticationFilter.java
              SecurityConfiguration.java
              ServiceConfiguration.java
            controller/
              CartController.java
              ProductController.java
              ServiceTestController.java
              UserController.java
            dto/
              auth/
                AuthenticationResponse.java
              cart/
                AddToCartRequest.java
                CartItemResponse.java
                CartResponse.java
                UpdateCartItemRequest.java
              notification/
                EmailRequest.java
                NotificationResponse.java
                SmsRequest.java
              payment/
                PaymentRequest.java
                PaymentResponse.java
                RefundRequest.java
                RefundResponse.java
                TransactionStatusResponse.java
              product/
                ProductResponse.java
              user/
                UserLoginRequest.java
                UserRegistrationRequest.java
                UserResponse.java
            entity/
              Cart.java
              CartItem.java
              Product.java
              User.java
            exception/
              EmailAlreadyExistsException.java
              InvalidCredentialsException.java
              UserNotFoundException.java
            repository/
              CartRepository.java
              ProductRepository.java
              UserRepository.java
            service/
              abstraction/
                NotificationServiceInterface.java
                PaymentGatewayInterface.java
              factory/
                ServiceFactory.java
              impl/
                stub/
                  StubNotificationService.java
                  StubPaymentGateway.java
                CustomUserDetailsService.java
                TokenBlacklistServiceImpl.java
                UserServiceImpl.java
              CartService.java
              ProductService.java
              TokenBlacklistService.java
              UserService.java
            util/
              JwtTokenUtil.java
            ShoppingCartApplication.java
    resources/
      application-dev.yml
      application-local.yml
      application-prod.yml
      application.properties
  test/
    java/
      pk/
        ai/
          shopping_cart/
            testdata/
              TestDataBuilder.java
            util/
              JwtTokenUtilTest.java
    resources/
      application-test.yml
.dockerignore
.gitattributes
.gitignore
build-docker.sh
docker-compose.prod.yml
docker-compose.yml
Dockerfile
init-mongo.js
mvnw
mvnw.cmd
pom.xml
README.md
SECURITY.md
settings.xml
test-api.sh
```

# Files

## File: .mvn/wrapper/maven-wrapper.properties
````
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
wrapperVersion=3.3.2
distributionType=only-script
distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.11/apache-maven-3.9.11-bin.zip
````

## File: src/main/java/pk/ai/shopping_cart/config/JwtAuthenticationFilter.java
````java
package pk.ai.shopping_cart.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import pk.ai.shopping_cart.util.JwtTokenUtil;
import pk.ai.shopping_cart.service.TokenBlacklistService;

import java.io.IOException;

/**
 * JWT Authentication Filter to validate JWT tokens in requests
 */
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;

    public JwtAuthenticationFilter(JwtTokenUtil jwtTokenUtil,
            UserDetailsService userDetailsService,
            TokenBlacklistService tokenBlacklistService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt)) {
                // Check if token is blacklisted
                if (tokenBlacklistService.isTokenBlacklisted(jwt)) {
                    log.debug("Token is blacklisted, denying access");
                    filterChain.doFilter(request, response);
                    return;
                }

                String username = jwtTokenUtil.getUsernameFromToken(jwt);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                    if (jwtTokenUtil.validateToken(jwt, userDetails.getUsername())) {
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        log.debug("Successfully authenticated user: {}", username);
                    }
                }
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from Authorization header
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/config/SecurityConfiguration.java
````java
package pk.ai.shopping_cart.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration for the shopping cart application
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Password encoder bean for hashing passwords
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Security filter chain configuration
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // Disable CSRF for API endpoints
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/users/register").permitAll() // Allow user registration
                        .requestMatchers("/api/users/login").permitAll() // Allow user login
                        .requestMatchers("/api/users/check-username/**").permitAll() // Allow username availability
                                                                                     // check
                        .requestMatchers("/api/users/check-email/**").permitAll() // Allow email availability check
                        .requestMatchers("/actuator/health").permitAll() // Allow health check for monitoring
                        .requestMatchers("/error").permitAll() // Allow error endpoint
                        .requestMatchers("/api/users/logout").authenticated() // Logout requires authentication
                        .anyRequest().authenticated() // Require authentication for all other endpoints
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // Add JWT filter

        return http.build();
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/config/ServiceConfiguration.java
````java
package pk.ai.shopping_cart.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import pk.ai.shopping_cart.service.factory.ServiceFactory;

/**
 * Service configuration for managing service abstraction layer
 */
@Slf4j
@Configuration
public class ServiceConfiguration {

    private final Environment environment;
    private final ServiceFactory serviceFactory;

    public ServiceConfiguration(Environment environment, ServiceFactory serviceFactory) {
        this.environment = environment;
        this.serviceFactory = serviceFactory;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        String[] activeProfiles = environment.getActiveProfiles();
        log.info("Application started with profiles: {}", String.join(", ", activeProfiles));
        log.info("Service configuration: {}", serviceFactory.getServiceConfiguration());

        if (serviceFactory.isUsingStubServices()) {
            log.warn("=================================================================");
            log.warn("WARNING: Application is running with STUB services!");
            log.warn("This is intended for development and testing only.");
            log.warn("Payment and notification operations will be simulated.");
            log.warn("=================================================================");
        } else {
            log.info("Application is running with external service integrations.");
        }
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/controller/CartController.java
````java
package pk.ai.shopping_cart.controller;

import pk.ai.shopping_cart.service.CartService;
import pk.ai.shopping_cart.dto.cart.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;

import jakarta.validation.Valid;

/**
 * REST controller for shopping cart operations
 */
@RestController
@RequestMapping("/api/cart")
@Slf4j
public class CartController {

    @Autowired
    private CartService cartService;

    /**
     * Get cart for current user
     */
    @GetMapping
    public ResponseEntity<CartResponse> getCart(@RequestParam String userId) {
        log.debug("Getting cart for user: {}", userId);
        CartResponse cart = cartService.getCart(userId);
        return ResponseEntity.ok(cart);
    }

    /**
     * Add item to cart
     */
    @PostMapping("/items")
    public ResponseEntity<CartResponse> addToCart(
            @RequestParam String userId,
            @Valid @RequestBody AddToCartRequest request) {
        log.debug("Adding item to cart for user: {}", userId);
        CartResponse cart = cartService.addToCart(userId, request);
        return ResponseEntity.ok(cart);
    }

    /**
     * Update cart item quantity
     */
    @PutMapping("/items")
    public ResponseEntity<CartResponse> updateCartItem(
            @RequestParam String userId,
            @Valid @RequestBody UpdateCartItemRequest request) {
        log.debug("Updating cart item for user: {}", userId);
        CartResponse cart = cartService.updateCartItem(userId, request);
        return ResponseEntity.ok(cart);
    }

    /**
     * Remove item from cart
     */
    @DeleteMapping("/items/{productId}")
    public ResponseEntity<CartResponse> removeFromCart(
            @RequestParam String userId,
            @PathVariable String productId) {
        log.debug("Removing item {} from cart for user: {}", productId, userId);
        CartResponse cart = cartService.removeFromCart(userId, productId);
        return ResponseEntity.ok(cart);
    }

}
````

## File: src/main/java/pk/ai/shopping_cart/controller/ProductController.java
````java
package pk.ai.shopping_cart.controller;

import pk.ai.shopping_cart.service.ProductService;
import pk.ai.shopping_cart.dto.product.ProductResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * REST controller for product catalog operations
 */
@RestController
@RequestMapping("/api/products")
@Slf4j
public class ProductController {

    @Autowired
    private ProductService productService;

    /**
     * Initialize sample products (for testing)
     */
    @PostMapping("/sample")
    public ResponseEntity<String> createSampleProducts() {
        log.debug("Creating sample products");
        productService.createSampleProducts();
        return ResponseEntity.ok("Sample products created");
    }

    /**
     * Get all available products
     */
    @GetMapping
    public ResponseEntity<List<ProductResponse>> getProducts() {
        log.debug("Getting all available products");
        List<ProductResponse> products = productService.getAvailableProducts();
        return ResponseEntity.ok(products);
    }

    /**
     * Get product by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ProductResponse> getProduct(@PathVariable String id) {
        log.debug("Getting product: {}", id);
        ProductResponse product = productService.getProduct(id);
        return ResponseEntity.ok(product);
    }

    /**
     * Search products
     */
    @GetMapping("/search")
    public ResponseEntity<List<ProductResponse>> searchProducts(@RequestParam String q) {
        log.debug("Searching products with term: {}", q);
        List<ProductResponse> products = productService.searchProducts(q);
        return ResponseEntity.ok(products);
    }

    /**
     * Get products by category
     */
    @GetMapping("/category/{category}")
    public ResponseEntity<List<ProductResponse>> getProductsByCategory(@PathVariable String category) {
        log.debug("Getting products for category: {}", category);
        List<ProductResponse> products = productService.getProductsByCategory(category);
        return ResponseEntity.ok(products);
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/controller/ServiceTestController.java
````java
package pk.ai.shopping_cart.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pk.ai.shopping_cart.dto.notification.EmailRequest;
import pk.ai.shopping_cart.dto.notification.NotificationResponse;
import pk.ai.shopping_cart.dto.notification.SmsRequest;
import pk.ai.shopping_cart.dto.payment.PaymentRequest;
import pk.ai.shopping_cart.dto.payment.PaymentResponse;
import pk.ai.shopping_cart.service.factory.ServiceFactory;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

/**
 * Test controller for verifying service abstraction layer
 * This will be replaced with proper business controllers in later phases
 */
@Slf4j
@RestController
@RequestMapping("/api/test")
public class ServiceTestController {

    private final ServiceFactory serviceFactory;

    public ServiceTestController(ServiceFactory serviceFactory) {
        this.serviceFactory = serviceFactory;
    }

    @GetMapping("/config")
    public ResponseEntity<Map<String, String>> getServiceConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("paymentGateway", serviceFactory.getPaymentGateway().getGatewayType());
        config.put("notificationService", serviceFactory.getNotificationService().getServiceType());
        config.put("usingStubs", String.valueOf(serviceFactory.isUsingStubServices()));
        return ResponseEntity.ok(config);
    }

    @PostMapping("/payment")
    public ResponseEntity<PaymentResponse> testPayment(@RequestBody Map<String, Object> request) {
        log.info("Testing payment with: {}", request);

        PaymentRequest paymentRequest = PaymentRequest.builder()
                .amount(new BigDecimal(request.get("amount").toString()))
                .currency(request.getOrDefault("currency", "USD").toString())
                .paymentMethodId(request.getOrDefault("paymentMethodId", "test_card").toString())
                .build();

        PaymentResponse response = serviceFactory.getPaymentGateway().processPayment(paymentRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/email")
    public ResponseEntity<NotificationResponse> testEmail(@RequestBody Map<String, String> request) {
        log.info("Testing email with: {}", request);

        EmailRequest emailRequest = EmailRequest.builder()
                .recipientEmail(request.get("email"))
                .subject(request.getOrDefault("subject", "Test Email"))
                .templateId(request.getOrDefault("templateId", "test_template"))
                .build();

        NotificationResponse response = serviceFactory.getNotificationService().sendEmail(emailRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/sms")
    public ResponseEntity<NotificationResponse> testSms(@RequestBody Map<String, String> request) {
        log.info("Testing SMS with: {}", request);

        SmsRequest smsRequest = SmsRequest.builder()
                .phoneNumber(request.get("phoneNumber"))
                .message(request.getOrDefault("message", "Test SMS"))
                .build();

        NotificationResponse response = serviceFactory.getNotificationService().sendSms(smsRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/payment/{transactionId}/status")
    public ResponseEntity<?> getPaymentStatus(@PathVariable String transactionId) {
        log.info("Getting payment status for: {}", transactionId);

        var response = serviceFactory.getPaymentGateway().getTransactionStatus(transactionId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/notification/{notificationId}/status")
    public ResponseEntity<NotificationResponse> getNotificationStatus(@PathVariable String notificationId) {
        log.info("Getting notification status for: {}", notificationId);

        NotificationResponse response = serviceFactory.getNotificationService().getNotificationStatus(notificationId);
        return ResponseEntity.ok(response);
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/controller/UserController.java
````java
package pk.ai.shopping_cart.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pk.ai.shopping_cart.dto.auth.AuthenticationResponse;
import pk.ai.shopping_cart.dto.user.UserLoginRequest;
import pk.ai.shopping_cart.dto.user.UserRegistrationRequest;
import pk.ai.shopping_cart.dto.user.UserResponse;
import pk.ai.shopping_cart.service.UserService;

import jakarta.validation.Valid;
import java.util.HashMap;
import java.util.Map;

/**
 * User management controller
 */
@Slf4j
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationRequest request) {
        try {
            log.info("User registration request for username: {}", request.getUsername());
            UserResponse user = userService.registerUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(user);
        } catch (RuntimeException e) {
            log.error("Registration failed: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody UserLoginRequest request) {
        try {
            log.info("User login request for: {}", request.getUsernameOrEmail());
            AuthenticationResponse response = userService.authenticateUser(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Authentication failed: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String authorizationHeader) {
        try {
            log.info("User logout request");

            // Extract token from Authorization header
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Authorization header missing or invalid");
                return ResponseEntity.badRequest().body(error);
            }

            String token = authorizationHeader.substring(7); // Remove "Bearer " prefix
            userService.logoutUser(token);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout successful");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Logout failed: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable String id) {
        try {
            UserResponse user = userService.getUserById(id);
            return ResponseEntity.ok(user);
        } catch (RuntimeException e) {
            log.error("User not found: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<?> getUserByUsername(@PathVariable String username) {
        try {
            UserResponse user = userService.getUserByUsername(username);
            return ResponseEntity.ok(user);
        } catch (RuntimeException e) {
            log.error("User not found: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/check-username/{username}")
    public ResponseEntity<Map<String, Boolean>> checkUsernameAvailability(@PathVariable String username) {
        boolean available = userService.isUsernameAvailable(username);
        Map<String, Boolean> response = new HashMap<>();
        response.put("available", available);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/check-email/{email}")
    public ResponseEntity<Map<String, Boolean>> checkEmailAvailability(@PathVariable String email) {
        boolean available = userService.isEmailAvailable(email);
        Map<String, Boolean> response = new HashMap<>();
        response.put("available", available);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateUserProfile(@PathVariable String id,
            @RequestBody UserResponse userUpdate) {
        try {
            UserResponse updatedUser = userService.updateUserProfile(id, userUpdate);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            log.error("User update failed: {}", e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/auth/AuthenticationResponse.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/dto/cart/AddToCartRequest.java
````java
package pk.ai.shopping_cart.dto.cart;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

/**
 * Request DTO for adding item to cart
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AddToCartRequest {

    @NotBlank(message = "Product ID is required")
    private String productId;

    @NotNull(message = "Quantity is required")
    @Positive(message = "Quantity must be positive")
    private Integer quantity;
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/cart/CartItemResponse.java
````java
package pk.ai.shopping_cart.dto.cart;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Response DTO for cart item
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CartItemResponse {

    private String productId;
    private String productSku;
    private String productName;
    private String productImageUrl;

    private BigDecimal unitPrice;
    private String currency;
    private Integer quantity;
    private BigDecimal totalPrice;

    private LocalDateTime addedAt;
    private LocalDateTime updatedAt;
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/cart/CartResponse.java
````java
package pk.ai.shopping_cart.dto.cart;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Response DTO for shopping cart
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CartResponse {

    private String id;
    private String userId;

    private List<CartItemResponse> items;

    private Integer totalItems;
    private BigDecimal totalPrice;
    private String currency;

    private String status;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime expiresAt;

    private boolean isEmpty;
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/cart/UpdateCartItemRequest.java
````java
package pk.ai.shopping_cart.dto.cart;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

/**
 * Request DTO for updating cart item quantity
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UpdateCartItemRequest {

    @NotBlank(message = "Product ID is required")
    private String productId;

    @NotNull(message = "Quantity is required")
    @Positive(message = "Quantity must be positive")
    private Integer quantity;
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/notification/EmailRequest.java
````java
package pk.ai.shopping_cart.dto.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Email notification request DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailRequest {

    private String recipientEmail;
    private String recipientName;
    private String subject;
    private String templateId;
    private Map<String, Object> templateData;
    private EmailMetadata metadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EmailMetadata {
        private String userId;
        private String orderId;
        private String priority;
        private String category;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/notification/NotificationResponse.java
````java
package pk.ai.shopping_cart.dto.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Notification response DTO containing delivery results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationResponse {

    private String notificationId;
    private NotificationStatus status;
    private String channel;
    private String recipient;
    private String errorMessage;
    private String errorCode;
    private LocalDateTime sentAt;
    private LocalDateTime deliveredAt;
    private NotificationMetadata metadata;

    public enum NotificationStatus {
        SENT,
        DELIVERED,
        FAILED,
        PENDING,
        BOUNCED,
        SPAM
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NotificationMetadata {
        private String providerMessageId;
        private String providerResponse;
        private String deliveryAttempts;
        private String costEstimate;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/notification/SmsRequest.java
````java
package pk.ai.shopping_cart.dto.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SMS notification request DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SmsRequest {

    private String phoneNumber;
    private String message;
    private String countryCode;
    private SmsMetadata metadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SmsMetadata {
        private String userId;
        private String orderId;
        private String messageType;
        private String priority;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/payment/PaymentRequest.java
````java
package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

/**
 * Payment request DTO for processing payments
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentRequest {

    private String orderId;
    private BigDecimal amount;
    private String currency;
    private String paymentMethodId;
    private String customerId;
    private String description;
    private PaymentMetadata metadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PaymentMetadata {
        private String customerEmail;
        private String customerName;
        private String orderReference;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/payment/PaymentResponse.java
````java
package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Payment response DTO containing payment processing results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentResponse {

    private String transactionId;
    private String orderId;
    private PaymentStatus status;
    private BigDecimal amount;
    private String currency;
    private String paymentMethodId;
    private String gatewayResponse;
    private String errorMessage;
    private String errorCode;
    private LocalDateTime processedAt;
    private PaymentMetadata metadata;

    public enum PaymentStatus {
        SUCCESS,
        FAILED,
        PENDING,
        CANCELLED,
        REQUIRES_ACTION
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PaymentMetadata {
        private String gatewayTransactionId;
        private String authorizationCode;
        private String riskScore;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/payment/RefundRequest.java
````java
package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

/**
 * Refund request DTO for processing refunds
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefundRequest {

    private String originalTransactionId;
    private String orderId;
    private BigDecimal amount;
    private String currency;
    private String reason;
    private RefundMetadata metadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RefundMetadata {
        private String requestedBy;
        private String refundReference;
        private String customerNotified;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/payment/RefundResponse.java
````java
package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Refund response DTO containing refund processing results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefundResponse {

    private String refundId;
    private String originalTransactionId;
    private String orderId;
    private RefundStatus status;
    private BigDecimal amount;
    private String currency;
    private String gatewayResponse;
    private String errorMessage;
    private String errorCode;
    private LocalDateTime processedAt;
    private RefundMetadata metadata;

    public enum RefundStatus {
        SUCCESS,
        FAILED,
        PENDING,
        CANCELLED
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RefundMetadata {
        private String gatewayRefundId;
        private String expectedProcessingTime;
        private String refundMethod;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/payment/TransactionStatusResponse.java
````java
package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Transaction status response DTO for checking payment status
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionStatusResponse {

    private String transactionId;
    private String orderId;
    private TransactionStatus status;
    private BigDecimal amount;
    private String currency;
    private String paymentMethodId;
    private LocalDateTime createdAt;
    private LocalDateTime lastUpdatedAt;
    private String gatewayStatus;
    private TransactionMetadata metadata;

    public enum TransactionStatus {
        CREATED,
        PROCESSING,
        SUCCESS,
        FAILED,
        CANCELLED,
        REFUNDED,
        PARTIALLY_REFUNDED
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TransactionMetadata {
        private String gatewayTransactionId;
        private String authorizationCode;
        private String riskAssessment;
        private String processingTimeMs;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/product/ProductResponse.java
````java
package pk.ai.shopping_cart.dto.product;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Response DTO for product
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProductResponse {

    private String id;
    private String sku;
    private String name;
    private String description;

    private BigDecimal price;
    private String currency;

    private Integer stockQuantity;
    private String category;
    private List<String> tags;

    private String imageUrl;
    private List<String> additionalImages;

    private String status;
    private boolean available;

    private ProductDimensionsResponse dimensions;
    private Double weight;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ProductDimensionsResponse {
        private Double length;
        private Double width;
        private Double height;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/user/UserLoginRequest.java
````java
package pk.ai.shopping_cart.dto.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;

/**
 * User login request DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserLoginRequest {

    @NotBlank(message = "Username or email is required")
    private String usernameOrEmail;

    @NotBlank(message = "Password is required")
    private String password;

    private boolean rememberMe;
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/user/UserRegistrationRequest.java
````java
package pk.ai.shopping_cart.dto.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * User registration request DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    private String password;

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name must not exceed 50 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50, message = "Last name must not exceed 50 characters")
    private String lastName;

    @Size(max = 20, message = "Phone number must not exceed 20 characters")
    private String phoneNumber;
}
````

## File: src/main/java/pk/ai/shopping_cart/dto/user/UserResponse.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/entity/Cart.java
````java
package pk.ai.shopping_cart.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Shopping cart entity
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "carts")
public class Cart {

    @Id
    private String id;

    @Indexed
    private String userId;

    @Builder.Default
    private List<CartItem> items = new ArrayList<>();

    private CartStatus status;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime expiresAt; // Cart expiration for cleanup

    public enum CartStatus {
        ACTIVE,
        ABANDONED,
        CHECKED_OUT,
        EXPIRED
    }

    /**
     * Add item to cart or update quantity if item already exists
     */
    public void addItem(CartItem newItem) {
        Optional<CartItem> existingItem = findItemByProductId(newItem.getProductId());

        if (existingItem.isPresent()) {
            // Update existing item quantity
            CartItem item = existingItem.get();
            item.updateQuantity(item.getQuantity() + newItem.getQuantity());
        } else {
            // Add new item
            newItem.setAddedAt(LocalDateTime.now());
            newItem.setUpdatedAt(LocalDateTime.now());
            items.add(newItem);
        }

        this.updatedAt = LocalDateTime.now();
    }

    /**
     * Remove item from cart
     */
    public boolean removeItem(String productId) {
        boolean removed = items.removeIf(item -> item.getProductId().equals(productId));
        if (removed) {
            this.updatedAt = LocalDateTime.now();
        }
        return removed;
    }

    /**
     * Update item quantity
     */
    public boolean updateItemQuantity(String productId, int quantity) {
        Optional<CartItem> item = findItemByProductId(productId);
        if (item.isPresent()) {
            if (quantity <= 0) {
                return removeItem(productId);
            } else {
                item.get().updateQuantity(quantity);
                this.updatedAt = LocalDateTime.now();
                return true;
            }
        }
        return false;
    }

    /**
     * Clear all items from cart
     */
    public void clear() {
        items.clear();
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * Find item by product ID
     */
    public Optional<CartItem> findItemByProductId(String productId) {
        return items.stream()
                .filter(item -> item.getProductId().equals(productId))
                .findFirst();
    }

    /**
     * Calculate total number of items in cart
     */
    public int getTotalItems() {
        return items.stream()
                .mapToInt(CartItem::getQuantity)
                .sum();
    }

    /**
     * Calculate total price of cart
     */
    public BigDecimal getTotalPrice() {
        return items.stream()
                .map(CartItem::getTotalPrice)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    /**
     * Check if cart is empty
     */
    public boolean isEmpty() {
        return items.isEmpty();
    }

    /**
     * Check if cart is expired
     */
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/entity/CartItem.java
````java
package pk.ai.shopping_cart.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Cart item representing a product in a shopping cart
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CartItem {

    private String productId;
    private String productSku;
    private String productName;

    private BigDecimal unitPrice;
    private String currency;

    private Integer quantity;

    private LocalDateTime addedAt;
    private LocalDateTime updatedAt;

    // Snapshot of product details at time of adding to cart
    private String productImageUrl;

    /**
     * Calculate total price for this cart item
     */
    public BigDecimal getTotalPrice() {
        if (unitPrice == null || quantity == null) {
            return BigDecimal.ZERO;
        }
        return unitPrice.multiply(BigDecimal.valueOf(quantity));
    }

    /**
     * Update quantity and timestamp
     */
    public void updateQuantity(int newQuantity) {
        this.quantity = newQuantity;
        this.updatedAt = LocalDateTime.now();
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/entity/Product.java
````java
package pk.ai.shopping_cart.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Product entity representing items in the catalog
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "products")
public class Product {

    @Id
    private String id;

    @Indexed(unique = true)
    private String sku; // Stock Keeping Unit

    private String name;
    private String description;

    private BigDecimal price;
    private String currency;

    private Integer stockQuantity;
    private String category;
    private List<String> tags;

    private String imageUrl;
    private List<String> additionalImages;

    private ProductStatus status;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Product dimensions and weight
    private ProductDimensions dimensions;
    private Double weight; // in kg

    public enum ProductStatus {
        ACTIVE,
        INACTIVE,
        OUT_OF_STOCK,
        DISCONTINUED
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ProductDimensions {
        private Double length; // in cm
        private Double width; // in cm
        private Double height; // in cm
    }

    /**
     * Check if product is available for purchase
     */
    public boolean isAvailable() {
        return status == ProductStatus.ACTIVE && stockQuantity != null && stockQuantity > 0;
    }

    /**
     * Check if product has sufficient stock
     */
    public boolean hasStock(int quantity) {
        return stockQuantity != null && stockQuantity >= quantity;
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/entity/User.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/exception/EmailAlreadyExistsException.java
````java
package pk.ai.shopping_cart.exception;

/**
 * Exception thrown when a user tries to register with an email that already
 * exists
 */
public class EmailAlreadyExistsException extends RuntimeException {

    public EmailAlreadyExistsException(String email) {
        super("Email already exists: " + email);
    }

    public EmailAlreadyExistsException(String email, Throwable cause) {
        super("Email already exists: " + email, cause);
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/exception/InvalidCredentialsException.java
````java
package pk.ai.shopping_cart.exception;

/**
 * Exception thrown when user authentication fails due to invalid credentials
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid credentials provided");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }

    public InvalidCredentialsException(String message, Throwable cause) {
        super(message, cause);
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/exception/UserNotFoundException.java
````java
package pk.ai.shopping_cart.exception;

/**
 * Exception thrown when a requested user is not found
 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String identifier) {
        super("User not found: " + identifier);
    }

    public UserNotFoundException(String identifier, Throwable cause) {
        super("User not found: " + identifier, cause);
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/repository/CartRepository.java
````java
package pk.ai.shopping_cart.repository;

import pk.ai.shopping_cart.entity.Cart;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository for Cart entity
 */
@Repository
public interface CartRepository extends MongoRepository<Cart, String> {

    /**
     * Find active cart by user ID
     */
    @Query("{ 'userId': ?0, 'status': 'ACTIVE' }")
    Optional<Cart> findActiveCartByUserId(String userId);

    /**
     * Find all carts by user ID
     */
    List<Cart> findByUserId(String userId);

    /**
     * Find carts by status
     */
    List<Cart> findByStatus(Cart.CartStatus status);

    /**
     * Find expired carts for cleanup
     */
    @Query("{ 'expiresAt': { $lt: ?0 }, 'status': 'ACTIVE' }")
    List<Cart> findExpiredCarts(LocalDateTime currentTime);

    /**
     * Find abandoned carts (not updated for a while)
     */
    @Query("{ 'updatedAt': { $lt: ?0 }, 'status': 'ACTIVE' }")
    List<Cart> findAbandonedCarts(LocalDateTime cutoffTime);
}
````

## File: src/main/java/pk/ai/shopping_cart/repository/ProductRepository.java
````java
package pk.ai.shopping_cart.repository;

import pk.ai.shopping_cart.entity.Product;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for Product entity
 */
@Repository
public interface ProductRepository extends MongoRepository<Product, String> {

    /**
     * Find product by SKU
     */
    Optional<Product> findBySku(String sku);

    /**
     * Find products by category
     */
    List<Product> findByCategory(String category);

    /**
     * Find products by status
     */
    List<Product> findByStatus(Product.ProductStatus status);

    /**
     * Find available products (active and in stock)
     */
    @Query("{ 'status': 'ACTIVE', 'stockQuantity': { $gt: 0 } }")
    List<Product> findAvailableProducts();

    /**
     * Search products by name or description
     */
    @Query("{ $or: [ { 'name': { $regex: ?0, $options: 'i' } }, { 'description': { $regex: ?0, $options: 'i' } } ] }")
    List<Product> searchProducts(String searchTerm);

    /**
     * Find products by category and status
     */
    List<Product> findByCategoryAndStatus(String category, Product.ProductStatus status);

    /**
     * Check if SKU exists
     */
    boolean existsBySku(String sku);
}
````

## File: src/main/java/pk/ai/shopping_cart/repository/UserRepository.java
````java
package pk.ai.shopping_cart.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import pk.ai.shopping_cart.entity.User;

import java.util.Optional;

/**
 * User repository for MongoDB operations
 */
@Repository
public interface UserRepository extends MongoRepository<User, String> {

    /**
     * Find user by username
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email
     */
    Optional<User> findByEmail(String email);

    /**
     * Find user by username or email
     */
    Optional<User> findByUsernameOrEmail(String username, String email);

    /**
     * Check if username exists
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists
     */
    boolean existsByEmail(String email);
}
````

## File: src/main/java/pk/ai/shopping_cart/service/abstraction/NotificationServiceInterface.java
````java
package pk.ai.shopping_cart.service.abstraction;

import pk.ai.shopping_cart.dto.notification.EmailRequest;
import pk.ai.shopping_cart.dto.notification.SmsRequest;
import pk.ai.shopping_cart.dto.notification.NotificationResponse;

/**
 * Notification Service abstraction interface
 * Allows switching between stub and external notification implementations
 */
public interface NotificationServiceInterface {

    /**
     * Send email notification
     */
    NotificationResponse sendEmail(EmailRequest emailRequest);

    /**
     * Send SMS notification
     */
    NotificationResponse sendSms(SmsRequest smsRequest);

    /**
     * Get notification delivery status
     */
    NotificationResponse getNotificationStatus(String notificationId);

    /**
     * Validate notification recipient
     */
    boolean validateRecipient(String recipient, String channel);

    /**
     * Get service type identifier
     */
    String getServiceType();
}
````

## File: src/main/java/pk/ai/shopping_cart/service/abstraction/PaymentGatewayInterface.java
````java
package pk.ai.shopping_cart.service.abstraction;

import pk.ai.shopping_cart.dto.payment.PaymentRequest;
import pk.ai.shopping_cart.dto.payment.PaymentResponse;
import pk.ai.shopping_cart.dto.payment.RefundRequest;
import pk.ai.shopping_cart.dto.payment.RefundResponse;
import pk.ai.shopping_cart.dto.payment.TransactionStatusResponse;

/**
 * Payment Gateway abstraction interface
 * Allows switching between stub and external payment implementations
 */
public interface PaymentGatewayInterface {

    /**
     * Process a payment transaction
     */
    PaymentResponse processPayment(PaymentRequest paymentRequest);

    /**
     * Validate an existing payment transaction
     */
    TransactionStatusResponse getTransactionStatus(String transactionId);

    /**
     * Process a refund for a transaction
     */
    RefundResponse refundPayment(RefundRequest refundRequest);

    /**
     * Validate payment method details
     */
    boolean validatePaymentMethod(String paymentMethodId);

    /**
     * Get gateway type identifier
     */
    String getGatewayType();
}
````

## File: src/main/java/pk/ai/shopping_cart/service/factory/ServiceFactory.java
````java
package pk.ai.shopping_cart.service.factory;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import pk.ai.shopping_cart.service.abstraction.NotificationServiceInterface;
import pk.ai.shopping_cart.service.abstraction.PaymentGatewayInterface;

import java.util.List;

/**
 * Service factory for managing service implementations based on active profiles
 * Automatically selects the appropriate implementation (stub or external)
 */
@Slf4j
@Component
public class ServiceFactory {

    private final PaymentGatewayInterface paymentGateway;
    private final NotificationServiceInterface notificationService;

    @Autowired
    public ServiceFactory(List<PaymentGatewayInterface> paymentGateways,
            List<NotificationServiceInterface> notificationServices) {

        // Select the first available payment gateway (Spring will inject based on
        // profile)
        this.paymentGateway = paymentGateways.stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No payment gateway implementation found"));

        // Select the first available notification service (Spring will inject based on
        // profile)
        this.notificationService = notificationServices.stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No notification service implementation found"));

        log.info("Service Factory initialized with:");
        log.info("  Payment Gateway: {}", paymentGateway.getGatewayType());
        log.info("  Notification Service: {}", notificationService.getServiceType());
    }

    /**
     * Get the active payment gateway implementation
     */
    public PaymentGatewayInterface getPaymentGateway() {
        return paymentGateway;
    }

    /**
     * Get the active notification service implementation
     */
    public NotificationServiceInterface getNotificationService() {
        return notificationService;
    }

    /**
     * Check if we're using stub implementations (useful for testing and
     * development)
     */
    public boolean isUsingStubServices() {
        return paymentGateway.getGatewayType().contains("STUB") ||
                notificationService.getServiceType().contains("STUB");
    }

    /**
     * Get service configuration info for debugging
     */
    public String getServiceConfiguration() {
        return String.format("Payment: %s, Notification: %s",
                paymentGateway.getGatewayType(),
                notificationService.getServiceType());
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/service/impl/stub/StubNotificationService.java
````java
package pk.ai.shopping_cart.service.impl.stub;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.dto.notification.EmailRequest;
import pk.ai.shopping_cart.dto.notification.NotificationResponse;
import pk.ai.shopping_cart.dto.notification.SmsRequest;
import pk.ai.shopping_cart.service.abstraction.NotificationServiceInterface;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Stub implementation of Notification Service for local/dev environments
 */
@Slf4j
@Service
@Profile({ "local", "dev", "test" })
public class StubNotificationService implements NotificationServiceInterface {

    private final Map<String, NotificationResponse> notificationStore = new HashMap<>();

    @Override
    public NotificationResponse sendEmail(EmailRequest emailRequest) {
        log.info("Sending stub email to: {} with subject: {}",
                emailRequest.getRecipientEmail(), emailRequest.getSubject());

        String notificationId = UUID.randomUUID().toString();

        // Simulate email sending
        NotificationResponse response = NotificationResponse.builder()
                .notificationId(notificationId)
                .channel("EMAIL")
                .recipient(emailRequest.getRecipientEmail())
                .status(NotificationResponse.NotificationStatus.SENT)
                .sentAt(LocalDateTime.now())
                .metadata(NotificationResponse.NotificationMetadata.builder()
                        .providerMessageId("stub_email_" + System.currentTimeMillis())
                        .providerResponse("STUB_EMAIL_PROVIDER_SUCCESS")
                        .deliveryAttempts("1")
                        .costEstimate("$0.00")
                        .build())
                .build();

        // Store for status lookup
        notificationStore.put(notificationId, response);

        log.info("Stub email sent successfully with ID: {}", notificationId);
        log.debug("Email content preview: Subject: '{}', Template: {}",
                emailRequest.getSubject(),
                emailRequest.getTemplateId() != null ? emailRequest.getTemplateId() : "none");

        return response;
    }

    @Override
    public NotificationResponse sendSms(SmsRequest smsRequest) {
        log.info("Sending stub SMS to: {}", smsRequest.getPhoneNumber());

        String notificationId = UUID.randomUUID().toString();

        // Simulate SMS sending
        NotificationResponse response = NotificationResponse.builder()
                .notificationId(notificationId)
                .channel("SMS")
                .recipient(smsRequest.getPhoneNumber())
                .status(NotificationResponse.NotificationStatus.SENT)
                .sentAt(LocalDateTime.now())
                .metadata(NotificationResponse.NotificationMetadata.builder()
                        .providerMessageId("stub_sms_" + System.currentTimeMillis())
                        .providerResponse("STUB_SMS_PROVIDER_SUCCESS")
                        .deliveryAttempts("1")
                        .costEstimate("$0.05")
                        .build())
                .build();

        // Store for status lookup
        notificationStore.put(notificationId, response);

        log.info("Stub SMS sent successfully with ID: {}", notificationId);
        log.debug("SMS content preview: Message length: {} chars",
                smsRequest.getMessage() != null ? smsRequest.getMessage().length() : 0);

        return response;
    }

    @Override
    public NotificationResponse getNotificationStatus(String notificationId) {
        log.info("Getting stub notification status for: {}", notificationId);

        NotificationResponse status = notificationStore.get(notificationId);
        if (status != null) {
            return status;
        }

        // Return not found response
        return NotificationResponse.builder()
                .notificationId(notificationId)
                .status(NotificationResponse.NotificationStatus.FAILED)
                .errorMessage("Notification not found in stub")
                .metadata(NotificationResponse.NotificationMetadata.builder()
                        .providerResponse("NOT_FOUND")
                        .build())
                .build();
    }

    @Override
    public boolean validateRecipient(String recipient, String channel) {
        log.info("Validating recipient in stub: {} for channel: {}", recipient, channel);

        if (recipient == null || recipient.trim().isEmpty()) {
            return false;
        }

        switch (channel.toUpperCase()) {
            case "EMAIL":
                // Basic email validation
                return recipient.contains("@") && recipient.contains(".");
            case "SMS":
                // Basic phone number validation (allow various formats)
                return recipient.matches(".*\\d.*") && recipient.length() >= 10;
            default:
                log.warn("Unknown channel type for validation: {}", channel);
                return false;
        }
    }

    @Override
    public String getServiceType() {
        return "STUB_NOTIFICATION_SERVICE";
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/service/impl/stub/StubPaymentGateway.java
````java
package pk.ai.shopping_cart.service.impl.stub;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.dto.payment.*;
import pk.ai.shopping_cart.service.abstraction.PaymentGatewayInterface;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Stub implementation of Payment Gateway for local/dev environments
 */
@Slf4j
@Service
@Profile({ "local", "dev", "test" })
public class StubPaymentGateway implements PaymentGatewayInterface {

    private final Map<String, TransactionStatusResponse> transactionStore = new HashMap<>();

    @Override
    public PaymentResponse processPayment(PaymentRequest paymentRequest) {
        log.info("Processing stub payment for amount: {} {}",
                paymentRequest.getAmount(), paymentRequest.getCurrency());

        String transactionId = UUID.randomUUID().toString();

        // Simulate different payment scenarios based on amount
        PaymentResponse.PaymentStatus status;
        String errorMessage = null;

        if (paymentRequest.getAmount().compareTo(new BigDecimal("1000")) > 0) {
            status = PaymentResponse.PaymentStatus.FAILED;
            errorMessage = "Stub: Amount exceeds limit for testing";
        } else if (paymentRequest.getAmount().compareTo(new BigDecimal("99.99")) == 0) {
            status = PaymentResponse.PaymentStatus.PENDING;
        } else {
            status = PaymentResponse.PaymentStatus.SUCCESS;
        }

        // Store transaction for status lookup
        TransactionStatusResponse transactionStatus = TransactionStatusResponse.builder()
                .transactionId(transactionId)
                .status(mapToTransactionStatus(status))
                .amount(paymentRequest.getAmount())
                .currency(paymentRequest.getCurrency())
                .paymentMethodId(paymentRequest.getPaymentMethodId())
                .createdAt(LocalDateTime.now())
                .lastUpdatedAt(LocalDateTime.now())
                .gatewayStatus("STUB_PROCESSED")
                .metadata(new TransactionStatusResponse.TransactionMetadata())
                .build();

        transactionStore.put(transactionId, transactionStatus);

        PaymentResponse response = PaymentResponse.builder()
                .transactionId(transactionId)
                .status(status)
                .amount(paymentRequest.getAmount())
                .currency(paymentRequest.getCurrency())
                .paymentMethodId(paymentRequest.getPaymentMethodId())
                .gatewayResponse("STUB_GATEWAY")
                .errorMessage(errorMessage)
                .processedAt(LocalDateTime.now())
                .metadata(PaymentResponse.PaymentMetadata.builder()
                        .gatewayTransactionId(transactionId)
                        .authorizationCode("STUB_AUTH_" + System.currentTimeMillis())
                        .riskScore("LOW")
                        .build())
                .build();

        log.info("Stub payment result: {} - {}", status, errorMessage != null ? errorMessage : "Success");
        return response;
    }

    @Override
    public RefundResponse refundPayment(RefundRequest refundRequest) {
        log.info("Processing stub refund for transaction: {}, amount: {}",
                refundRequest.getOriginalTransactionId(), refundRequest.getAmount());

        String refundId = UUID.randomUUID().toString();

        // Simulate refund processing
        RefundResponse.RefundStatus status = RefundResponse.RefundStatus.SUCCESS;

        RefundResponse response = RefundResponse.builder()
                .refundId(refundId)
                .originalTransactionId(refundRequest.getOriginalTransactionId())
                .status(status)
                .amount(refundRequest.getAmount())
                .currency(refundRequest.getCurrency())
                .gatewayResponse("STUB_GATEWAY")
                .processedAt(LocalDateTime.now())
                .metadata(RefundResponse.RefundMetadata.builder()
                        .gatewayRefundId(refundId)
                        .build())
                .build();

        log.info("Stub refund result: {} - Success", status);
        return response;
    }

    @Override
    public TransactionStatusResponse getTransactionStatus(String transactionId) {
        log.info("Getting stub transaction status for: {}", transactionId);

        TransactionStatusResponse status = transactionStore.get(transactionId);
        if (status != null) {
            return status;
        }

        // Return not found response
        return TransactionStatusResponse.builder()
                .transactionId(transactionId)
                .status(TransactionStatusResponse.TransactionStatus.FAILED)
                .gatewayStatus("NOT_FOUND")
                .metadata(new TransactionStatusResponse.TransactionMetadata())
                .build();
    }

    @Override
    public boolean validatePaymentMethod(String paymentMethodId) {
        log.info("Validating payment method in stub: {}", paymentMethodId);

        // Stub validation - accept most common payment method IDs
        return paymentMethodId != null &&
                (paymentMethodId.toLowerCase().contains("card") ||
                        paymentMethodId.toLowerCase().contains("wallet") ||
                        paymentMethodId.toLowerCase().contains("bank") ||
                        paymentMethodId.startsWith("pm_")); // Stripe-like format
    }

    @Override
    public String getGatewayType() {
        return "STUB_GATEWAY";
    }

    private TransactionStatusResponse.TransactionStatus mapToTransactionStatus(
            PaymentResponse.PaymentStatus paymentStatus) {
        switch (paymentStatus) {
            case SUCCESS:
                return TransactionStatusResponse.TransactionStatus.SUCCESS;
            case PENDING:
                return TransactionStatusResponse.TransactionStatus.PROCESSING;
            case FAILED:
            default:
                return TransactionStatusResponse.TransactionStatus.FAILED;
        }
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/service/impl/CustomUserDetailsService.java
````java
package pk.ai.shopping_cart.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.entity.User;
import pk.ai.shopping_cart.repository.UserRepository;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * UserDetailsService implementation for Spring Security authentication
 */
@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);

        User user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return new CustomUserPrincipal(user);
    }

    /**
     * Custom UserDetails implementation
     */
    public static class CustomUserPrincipal implements UserDetails {

        private final User user;

        public CustomUserPrincipal(User user) {
            this.user = user;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            Set<User.UserRole> roles = user.getRoles();
            if (roles == null || roles.isEmpty()) {
                return Set.of(new SimpleGrantedAuthority("ROLE_USER"));
            }

            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                    .collect(Collectors.toSet());
        }

        @Override
        public String getPassword() {
            return user.getPasswordHash();
        }

        @Override
        public String getUsername() {
            return user.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true; // We can add account expiration logic later if needed
        }

        @Override
        public boolean isAccountNonLocked() {
            return user.getStatus() != User.UserStatus.SUSPENDED;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true; // We can add credential expiration logic later if needed
        }

        @Override
        public boolean isEnabled() {
            return user.getStatus() == User.UserStatus.ACTIVE ||
                    user.getStatus() == User.UserStatus.PENDING_VERIFICATION;
        }

        /**
         * Get the underlying User entity
         */
        public User getUser() {
            return user;
        }
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/service/impl/TokenBlacklistServiceImpl.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/service/impl/UserServiceImpl.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/service/CartService.java
````java
package pk.ai.shopping_cart.service;

import pk.ai.shopping_cart.entity.Cart;
import pk.ai.shopping_cart.entity.CartItem;
import pk.ai.shopping_cart.entity.Product;
import pk.ai.shopping_cart.repository.CartRepository;
import pk.ai.shopping_cart.repository.ProductRepository;
import pk.ai.shopping_cart.dto.cart.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service for shopping cart operations
 */
@Service
@Slf4j
public class CartService {

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private ProductRepository productRepository;

    /**
     * Get or create cart for user
     */
    public Cart getOrCreateCart(String userId) {
        Optional<Cart> existingCart = cartRepository.findActiveCartByUserId(userId);

        if (existingCart.isPresent()) {
            Cart cart = existingCart.get();

            // Check if cart is expired
            if (cart.isExpired()) {
                cart.setStatus(Cart.CartStatus.EXPIRED);
                cartRepository.save(cart);
                return createNewCart(userId);
            }

            return cart;
        }

        return createNewCart(userId);
    }

    /**
     * Add item to cart
     */
    public CartResponse addToCart(String userId, AddToCartRequest request) {
        log.debug("Adding product {} to cart for user {}", request.getProductId(), userId);

        // Validate product exists and is available
        Product product = productRepository.findById(request.getProductId())
                .orElseThrow(() -> new RuntimeException("Product not found: " + request.getProductId()));

        if (!product.isAvailable()) {
            throw new RuntimeException("Product is not available: " + product.getName());
        }

        if (!product.hasStock(request.getQuantity())) {
            throw new RuntimeException("Insufficient stock for product: " + product.getName());
        }

        // Get or create cart
        Cart cart = getOrCreateCart(userId);

        // Create cart item
        CartItem cartItem = CartItem.builder()
                .productId(product.getId())
                .productSku(product.getSku())
                .productName(product.getName())
                .unitPrice(product.getPrice())
                .currency(product.getCurrency())
                .quantity(request.getQuantity())
                .productImageUrl(product.getImageUrl())
                .build();

        // Add item to cart
        cart.addItem(cartItem);

        // Extend cart expiration
        cart.setExpiresAt(LocalDateTime.now().plusDays(7)); // 7 days from now

        // Save cart
        cart = cartRepository.save(cart);

        log.debug("Added {} x {} to cart for user {}", request.getQuantity(), product.getName(), userId);

        return convertToCartResponse(cart);
    }

    /**
     * Update cart item quantity
     */
    public CartResponse updateCartItem(String userId, UpdateCartItemRequest request) {
        log.debug("Updating cart item {} for user {}", request.getProductId(), userId);

        Cart cart = cartRepository.findActiveCartByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Cart not found for user: " + userId));

        boolean updated = cart.updateItemQuantity(request.getProductId(), request.getQuantity());

        if (!updated) {
            throw new RuntimeException("Product not found in cart: " + request.getProductId());
        }

        cart = cartRepository.save(cart);

        log.debug("Updated cart item {} quantity to {} for user {}",
                request.getProductId(), request.getQuantity(), userId);

        return convertToCartResponse(cart);
    }

    /**
     * Remove item from cart
     */
    public CartResponse removeFromCart(String userId, String productId) {
        log.debug("Removing product {} from cart for user {}", productId, userId);

        Cart cart = cartRepository.findActiveCartByUserId(userId)
                .orElseThrow(() -> new RuntimeException("Cart not found for user: " + userId));

        boolean removed = cart.removeItem(productId);

        if (!removed) {
            throw new RuntimeException("Product not found in cart: " + productId);
        }

        cart = cartRepository.save(cart);

        log.debug("Removed product {} from cart for user {}", productId, userId);

        return convertToCartResponse(cart);
    }

    /**
     * Get cart for user
     */
    public CartResponse getCart(String userId) {
        Cart cart = getOrCreateCart(userId);
        return convertToCartResponse(cart);
    }

    /**
     * Create new cart for user
     */
    private Cart createNewCart(String userId) {
        Cart cart = Cart.builder()
                .userId(userId)
                .status(Cart.CartStatus.ACTIVE)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusDays(7)) // 7 days expiration
                .build();

        return cartRepository.save(cart);
    }

    /**
     * Convert Cart entity to CartResponse DTO
     */
    private CartResponse convertToCartResponse(Cart cart) {
        List<CartItemResponse> itemResponses = cart.getItems().stream()
                .map(this::convertToCartItemResponse)
                .collect(Collectors.toList());

        return CartResponse.builder()
                .id(cart.getId())
                .userId(cart.getUserId())
                .items(itemResponses)
                .totalItems(cart.getTotalItems())
                .totalPrice(cart.getTotalPrice())
                .currency("USD") // Default currency
                .status(cart.getStatus().toString())
                .createdAt(cart.getCreatedAt())
                .updatedAt(cart.getUpdatedAt())
                .expiresAt(cart.getExpiresAt())
                .isEmpty(cart.isEmpty())
                .build();
    }

    /**
     * Convert CartItem entity to CartItemResponse DTO
     */
    private CartItemResponse convertToCartItemResponse(CartItem item) {
        return CartItemResponse.builder()
                .productId(item.getProductId())
                .productSku(item.getProductSku())
                .productName(item.getProductName())
                .productImageUrl(item.getProductImageUrl())
                .unitPrice(item.getUnitPrice())
                .currency(item.getCurrency())
                .quantity(item.getQuantity())
                .totalPrice(item.getTotalPrice())
                .addedAt(item.getAddedAt())
                .updatedAt(item.getUpdatedAt())
                .build();
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/service/ProductService.java
````java
package pk.ai.shopping_cart.service;

import pk.ai.shopping_cart.entity.Product;
import pk.ai.shopping_cart.repository.ProductRepository;
import pk.ai.shopping_cart.dto.product.ProductResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for product catalog operations
 */
@Service
@Slf4j
public class ProductService {

    @Autowired
    private ProductRepository productRepository;

    /**
     * Create sample products for testing
     */
    public void createSampleProducts() {
        if (productRepository.count() == 0) {
            log.info("Creating sample products...");

            List<Product> sampleProducts = List.of(
                    Product.builder()
                            .sku("LAPTOP-001")
                            .name("Gaming Laptop")
                            .description("High-performance gaming laptop with RTX graphics")
                            .price(new BigDecimal("1299.99"))
                            .currency("USD")
                            .stockQuantity(10)
                            .category("Electronics")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/laptop.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build(),

                    Product.builder()
                            .sku("PHONE-001")
                            .name("Smartphone Pro")
                            .description("Latest smartphone with advanced camera system")
                            .price(new BigDecimal("899.99"))
                            .currency("USD")
                            .stockQuantity(25)
                            .category("Electronics")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/phone.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build(),

                    Product.builder()
                            .sku("BOOK-001")
                            .name("Programming Guide")
                            .description("Comprehensive guide to modern programming")
                            .price(new BigDecimal("49.99"))
                            .currency("USD")
                            .stockQuantity(50)
                            .category("Books")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/book.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build(),

                    Product.builder()
                            .sku("HEADPHONES-001")
                            .name("Wireless Headphones")
                            .description("Premium wireless headphones with noise cancellation")
                            .price(new BigDecimal("199.99"))
                            .currency("USD")
                            .stockQuantity(15)
                            .category("Electronics")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/headphones.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build());

            productRepository.saveAll(sampleProducts);
            log.info("Created {} sample products", sampleProducts.size());
        }
    }

    /**
     * Get all available products
     */
    public List<ProductResponse> getAvailableProducts() {
        List<Product> products = productRepository.findAvailableProducts();
        return products.stream()
                .map(this::convertToProductResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get product by ID
     */
    public ProductResponse getProduct(String id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found: " + id));
        return convertToProductResponse(product);
    }

    /**
     * Search products
     */
    public List<ProductResponse> searchProducts(String searchTerm) {
        List<Product> products = productRepository.searchProducts(searchTerm);
        return products.stream()
                .map(this::convertToProductResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get products by category
     */
    public List<ProductResponse> getProductsByCategory(String category) {
        List<Product> products = productRepository.findByCategoryAndStatus(category, Product.ProductStatus.ACTIVE);
        return products.stream()
                .map(this::convertToProductResponse)
                .collect(Collectors.toList());
    }

    /**
     * Convert Product entity to ProductResponse DTO
     */
    private ProductResponse convertToProductResponse(Product product) {
        ProductResponse.ProductDimensionsResponse dimensions = null;
        if (product.getDimensions() != null) {
            dimensions = ProductResponse.ProductDimensionsResponse.builder()
                    .length(product.getDimensions().getLength())
                    .width(product.getDimensions().getWidth())
                    .height(product.getDimensions().getHeight())
                    .build();
        }

        return ProductResponse.builder()
                .id(product.getId())
                .sku(product.getSku())
                .name(product.getName())
                .description(product.getDescription())
                .price(product.getPrice())
                .currency(product.getCurrency())
                .stockQuantity(product.getStockQuantity())
                .category(product.getCategory())
                .tags(product.getTags())
                .imageUrl(product.getImageUrl())
                .additionalImages(product.getAdditionalImages())
                .status(product.getStatus().toString())
                .available(product.isAvailable())
                .dimensions(dimensions)
                .weight(product.getWeight())
                .createdAt(product.getCreatedAt())
                .updatedAt(product.getUpdatedAt())
                .build();
    }
}
````

## File: src/main/java/pk/ai/shopping_cart/service/TokenBlacklistService.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/service/UserService.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/util/JwtTokenUtil.java
````java
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
````

## File: src/main/java/pk/ai/shopping_cart/ShoppingCartApplication.java
````java
package pk.ai.shopping_cart;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableMongoRepositories
@EnableScheduling
public class ShoppingCartApplication {

	public static void main(String[] args) {
		SpringApplication.run(ShoppingCartApplication.class, args);
	}

}
````

## File: src/main/resources/application-dev.yml
````yaml
spring:
  application:
    name: shopping-cart
  data:
    mongodb:
      host: ${MONGO_HOST:localhost}
      port: ${MONGO_PORT:27017}
      database: ${MONGO_DATABASE:shopping-cart-dev}

server:
  port: 8080

# Service configurations for development
services:
  payment:
    type: stub
    config:
      success-rate: 90
      response-delay: 200
      test-scenarios: true
  notification:
    type: stub
    config:
      log-to-console: true
      save-to-file: false
      simulate-failures: 5

# JWT Configuration
jwt:
  secret: ${JWT_SECRET:myDevSecretKeyForDevelopmentEnvironment123456789}
  expiration: 86400000 # 24 hours

# Actuator configuration
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,env
  endpoint:
    health:
      show-details: when-authorized

# Logging configuration
logging:
  level:
    pk.ai.shopping_cart: INFO
    org.springframework.security: WARN
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%level] %logger{36} - %msg%n"
````

## File: src/main/resources/application-local.yml
````yaml
spring:
  application:
    name: shopping-cart
  data:
    mongodb:
      host: localhost
      port: 27017
      database: shopping-cart-local
  security:
    enabled: false
  
server:
  port: 8081

# Service configurations for local development
services:
  payment:
    type: stub
    config:
      success-rate: 85
      response-delay: 500
      test-scenarios: true
  notification:
    type: stub
    config:
      log-to-console: true
      save-to-file: true
      simulate-failures: 10

# JWT Configuration
jwt:
  secret: myVeryLongSecretKeyThatIsAtLeast512BitsForHS512AlgorithmSecurityMyVeryLongSecretKeyThatIsAtLeast512BitsForHS512AlgorithmSecurity
  expiration: 86400000 # 24 hours

# Actuator configuration
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always

# Logging configuration
logging:
  level:
    pk.ai.shopping_cart: DEBUG
    org.springframework.security: DEBUG
pattern:
  console: "%d{yyyy-MM-dd HH:mm:ss} [%c] - %msg%n"
````

## File: src/main/resources/application-prod.yml
````yaml
spring:
  application:
    name: shopping-cart
  data:
    mongodb:
      host: ${MONGO_HOST}
      port: ${MONGO_PORT:27017}
      database: ${MONGO_DATABASE}
      username: ${MONGO_USERNAME}
      password: ${MONGO_PASSWORD}

server:
  port: 8080

# Service configurations for production
services:
  payment:
    type: external
    provider: stripe
    config:
      api-key: ${STRIPE_API_KEY}
      webhook-secret: ${STRIPE_WEBHOOK_SECRET}
      timeout: 30000
  notification:
    type: external
    providers:
      email: sendgrid
      sms: twilio
    config:
      sendgrid-api-key: ${SENDGRID_API_KEY}
      twilio-account-sid: ${TWILIO_ACCOUNT_SID}
      twilio-auth-token: ${TWILIO_AUTH_TOKEN}

# JWT Configuration
jwt:
  secret: ${JWT_SECRET}
  expiration: 3600000 # 1 hour for production

# Actuator configuration
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: never

# Logging configuration
logging:
  level:
    pk.ai.shopping_cart: WARN
    org.springframework.security: ERROR
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%level] %logger{36} - %msg%n"
````

## File: src/main/resources/application.properties
````
spring.application.name=shopping-cart

# Active profile - change this to switch environments
spring.profiles.active=local

# Server configuration
server.port=8080

# MongoDB configuration (will be overridden by profile-specific configs)
spring.data.mongodb.host=${MONGO_HOST:localhost}
spring.data.mongodb.port=${MONGO_PORT:27017}
spring.data.mongodb.database=${MONGO_DATABASE:shopping-cart}

# Actuator configuration for health checks
management.endpoints.web.exposure.include=health,info,metrics
management.endpoint.health.show-details=when-authorized
management.health.mongo.enabled=true

# API Documentation
springdoc.api-docs.path=/api-docs
springdoc.swagger-ui.path=/swagger-ui.html
````

## File: src/test/java/pk/ai/shopping_cart/testdata/TestDataBuilder.java
````java
package pk.ai.shopping_cart.testdata;

import pk.ai.shopping_cart.dto.cart.AddToCartRequest;
import pk.ai.shopping_cart.dto.cart.UpdateCartItemRequest;
import pk.ai.shopping_cart.dto.user.UserLoginRequest;
import pk.ai.shopping_cart.dto.user.UserRegistrationRequest;
import pk.ai.shopping_cart.entity.Cart;
import pk.ai.shopping_cart.entity.CartItem;
import pk.ai.shopping_cart.entity.Product;
import pk.ai.shopping_cart.entity.User;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

/**
 * Test data builder for creating consistent test entities and DTOs
 */
public class TestDataBuilder {

    // User Test Data
    public static User.UserBuilder createTestUserBuilder() {
        Set<User.UserRole> roles = new HashSet<>();
        roles.add(User.UserRole.USER);

        return User.builder()
                .id("test-user-id")
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$10$encoded.password.hash")
                .firstName("Test")
                .lastName("User")
                .phoneNumber("+1234567890")
                .status(User.UserStatus.ACTIVE)
                .roles(roles)
                .emailVerified(true)
                .phoneVerified(false)
                .twoFactorEnabled(false)
                .createdAt(LocalDateTime.now().minusDays(30))
                .lastUpdatedAt(LocalDateTime.now().minusDays(1))
                .lastLoginAt(LocalDateTime.now().minusHours(2));
    }

    public static User createTestUser() {
        return createTestUserBuilder().build();
    }

    public static User createTestUserWithId(String id) {
        return createTestUserBuilder().id(id).build();
    }

    public static User createTestUserWithUsername(String username) {
        return createTestUserBuilder().username(username).build();
    }

    public static User createTestUserWithEmail(String email) {
        return createTestUserBuilder().email(email).build();
    }

    public static UserRegistrationRequest createUserRegistrationRequest() {
        return UserRegistrationRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("SecurePass123!")
                .firstName("New")
                .lastName("User")
                .phoneNumber("+1987654321")
                .build();
    }

    public static UserLoginRequest createUserLoginRequest() {
        return UserLoginRequest.builder()
                .usernameOrEmail("testuser")
                .password("correctpassword")
                .build();
    }

    // Product Test Data
    public static Product.ProductBuilder createTestProductBuilder() {
        return Product.builder()
                .id("test-product-id")
                .sku("TEST-001")
                .name("Test Product")
                .description("A test product for unit testing")
                .price(new BigDecimal("99.99"))
                .currency("USD")
                .stockQuantity(100)
                .category("Electronics")
                .status(Product.ProductStatus.ACTIVE)
                .imageUrl("https://example.com/test-product.jpg")
                .weight(1.5)
                .createdAt(LocalDateTime.now().minusDays(10))
                .updatedAt(LocalDateTime.now().minusDays(1));
    }

    public static Product createTestProduct() {
        return createTestProductBuilder().build();
    }

    public static Product createTestProductWithId(String id) {
        return createTestProductBuilder().id(id).build();
    }

    public static Product createTestProductWithSku(String sku) {
        return createTestProductBuilder().sku(sku).build();
    }

    public static Product createTestProductWithStock(int stockQuantity) {
        return createTestProductBuilder().stockQuantity(stockQuantity).build();
    }

    public static Product createTestProductWithStatus(Product.ProductStatus status) {
        return createTestProductBuilder().status(status).build();
    }

    public static Product createOutOfStockProduct() {
        return createTestProductBuilder()
                .stockQuantity(0)
                .status(Product.ProductStatus.OUT_OF_STOCK)
                .build();
    }

    // Cart Test Data
    public static Cart.CartBuilder createTestCartBuilder() {
        return Cart.builder()
                .id("test-cart-id")
                .userId("test-user-id")
                .items(new ArrayList<>())
                .status(Cart.CartStatus.ACTIVE)
                .createdAt(LocalDateTime.now().minusHours(2))
                .updatedAt(LocalDateTime.now().minusMinutes(30))
                .expiresAt(LocalDateTime.now().plusDays(7));
    }

    public static Cart createTestCart() {
        return createTestCartBuilder().build();
    }

    public static Cart createTestCartWithUserId(String userId) {
        return createTestCartBuilder().userId(userId).build();
    }

    public static Cart createExpiredCart() {
        return createTestCartBuilder()
                .expiresAt(LocalDateTime.now().minusHours(1))
                .status(Cart.CartStatus.EXPIRED)
                .build();
    }

    // CartItem Test Data
    public static CartItem.CartItemBuilder createTestCartItemBuilder() {
        return CartItem.builder()
                .productId("test-product-id")
                .productSku("TEST-001")
                .productName("Test Product")
                .unitPrice(new BigDecimal("99.99"))
                .currency("USD")
                .quantity(2)
                .productImageUrl("https://example.com/test-product.jpg")
                .addedAt(LocalDateTime.now().minusHours(1))
                .updatedAt(LocalDateTime.now().minusMinutes(30));
    }

    public static CartItem createTestCartItem() {
        return createTestCartItemBuilder().build();
    }

    public static CartItem createTestCartItemWithProductId(String productId) {
        return createTestCartItemBuilder().productId(productId).build();
    }

    public static CartItem createTestCartItemWithQuantity(int quantity) {
        return createTestCartItemBuilder().quantity(quantity).build();
    }

    // Request DTOs
    public static AddToCartRequest createAddToCartRequest() {
        return AddToCartRequest.builder()
                .productId("test-product-id")
                .quantity(2)
                .build();
    }

    public static AddToCartRequest createAddToCartRequestWithProductId(String productId) {
        return AddToCartRequest.builder()
                .productId(productId)
                .quantity(1)
                .build();
    }

    public static AddToCartRequest createAddToCartRequestWithQuantity(int quantity) {
        return AddToCartRequest.builder()
                .productId("test-product-id")
                .quantity(quantity)
                .build();
    }

    public static UpdateCartItemRequest createUpdateCartItemRequest() {
        return UpdateCartItemRequest.builder()
                .productId("test-product-id")
                .quantity(3)
                .build();
    }

    public static UpdateCartItemRequest createUpdateCartItemRequestWithQuantity(int quantity) {
        return UpdateCartItemRequest.builder()
                .productId("test-product-id")
                .quantity(quantity)
                .build();
    }

    // Utility methods for creating carts with items
    public static Cart createCartWithItems(String userId, CartItem... items) {
        Cart cart = createTestCartWithUserId(userId);
        for (CartItem item : items) {
            cart.getItems().add(item);
        }
        return cart;
    }

    public static Cart createCartWithSingleItem(String userId, String productId, int quantity) {
        CartItem item = createTestCartItemWithProductId(productId);
        item.setQuantity(quantity);
        return createCartWithItems(userId, item);
    }

    // Authentication test helpers
    public static UserLoginRequest createInvalidLoginRequest() {
        return UserLoginRequest.builder()
                .usernameOrEmail("testuser")
                .password("wrongpassword")
                .build();
    }

    public static UserRegistrationRequest createInvalidRegistrationRequest() {
        return UserRegistrationRequest.builder()
                .username("") // Invalid username
                .email("invalid-email")
                .password("weak")
                .firstName("")
                .lastName("")
                .build();
    }

    // Service Factory test data
    public static String createTestJwtToken() {
        return "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTYzMDQwNDAwMCwiZXhwIjoxNjMwNDkwNDAwfQ.test-signature";
    }

    public static String createExpiredJwtToken() {
        return "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTYzMDMwMDAwMCwiZXhwIjoxNjMwMzAxMDAwfQ.expired-signature";
    }
}
````

## File: src/test/java/pk/ai/shopping_cart/util/JwtTokenUtilTest.java
````java
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
````

## File: src/test/resources/application-test.yml
````yaml
spring:
  application:
    name: shopping-cart-test
  data:
    mongodb:
      # Use embedded MongoDB for unit tests
      host: localhost
      port: 27017
      database: shopping-cart-test

server:
  port: 0  # Random port for testing

# Service configurations for testing (use stubs)
services:
  payment:
    type: stub
    config:
      success-rate: 100
      response-delay: 0
      test-scenarios: true
  notification:
    type: stub
    config:
      log-to-console: false
      save-to-file: false
      simulate-failures: 0

# JWT Configuration for testing
jwt:
  secret: testSecretKeyForUnitTestingThatIsLongEnoughForHS512Algorithm123456789
  expiration: 3600000 # 1 hour for testing

# Logging configuration for tests
logging:
  level:
    pk.ai.shopping_cart: DEBUG
    org.springframework.test: DEBUG
    org.springframework.security: WARN
    org.mongodb: WARN
    
# Disable MongoDB auto-configuration for unit tests when needed
management:
  endpoints:
    enabled-by-default: false
````

## File: .dockerignore
````
# Maven
target/
!target/*.jar
pom.xml.tag
pom.xml.releaseBackup
pom.xml.versionsBackup
pom.xml.next
release.properties
dependency-reduced-pom.xml
buildNumber.properties
.mvn/timing.properties
.mvn/wrapper/maven-wrapper.jar

# IDE
.idea/
*.iws
*.iml
*.ipr
.vscode/
.classpath
.project
.settings/
.factorypath

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Git
.git/
.gitignore

# Docker
Dockerfile
.dockerignore
docker-compose*.yml

# Documentation
README.md
HELP.md
*.md

# Other
.env
.env.local
.env.*.local
node_modules/
````

## File: .gitattributes
````
/mvnw text eol=lf
*.cmd text eol=crlf
````

## File: .gitignore
````
HELP.md
target/
.mvn/wrapper/maven-wrapper.jar
!**/src/main/**/target/
!**/src/test/**/target/

### STS ###
.apt_generated
.classpath
.factorypath
.project
.settings
.springBeans
.sts4-cache

### IntelliJ IDEA ###
.idea
*.iws
*.iml
*.ipr

### NetBeans ###
/nbproject/private/
/nbbuild/
/dist/
/nbdist/
/.nb-gradle/
build/
!**/src/main/**/build/
!**/src/test/**/build/

### VS Code ###
.vscode/
````

## File: build-docker.sh
````bash
#!/bin/bash

# Shopping Cart Docker Build Script

set -e

echo "Building Shopping Cart Docker image..."

# Get the project version from pom.xml
VERSION=$(mvn -q -Dexec.executable=echo -Dexec.args='${project.version}' --non-recursive exec:exec)

# Build the Docker image
docker build -t shopping-cart:${VERSION} -t shopping-cart:latest .

echo "Docker image built successfully!"
echo "Tags: shopping-cart:${VERSION}, shopping-cart:latest"

# Optional: Show image info
docker images shopping-cart
````

## File: docker-compose.prod.yml
````yaml
version: '3.8'

services:
  shopping-cart-app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - MONGO_HOST=mongodb
      - MONGO_PORT=27017
      - MONGO_DATABASE=shopping-cart
      - JAVA_OPTS=-Xmx256m -Xms128m -XX:+UseG1GC
    depends_on:
      mongodb:
        condition: service_healthy
    networks:
      - shopping-cart-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  mongodb:
    image: mongo:7.0
    container_name: shopping-cart-mongodb-prod
    environment:
      - MONGO_INITDB_DATABASE=shopping-cart
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=admin123
    volumes:
      - mongodb_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro
    networks:
      - shopping-cart-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  mongodb_data:
    driver: local

networks:
  shopping-cart-network:
    driver: bridge
````

## File: docker-compose.yml
````yaml
version: '3.8'

services:
  shopping-cart-app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - MONGO_HOST=mongodb
      - MONGO_PORT=27017
      - MONGO_DATABASE=shopping-cart
      - SPRING_PROFILES_ACTIVE=dev
    depends_on:
      - mongodb
    networks:
      - shopping-cart-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

  mongodb:
    image: mongo:7.0
    container_name: shopping-cart-mongodb
    ports:
      - "27017:27017"
    environment:
      - MONGO_INITDB_DATABASE=shopping-cart
    volumes:
      - mongodb_data:/data/db
      - ./init-mongo.js:/docker-entrypoint-initdb.d/init-mongo.js:ro
    networks:
      - shopping-cart-network
    restart: unless-stopped

volumes:
  mongodb_data:
    driver: local

networks:
  shopping-cart-network:
    driver: bridge
````

## File: Dockerfile
````dockerfile
# Multi-stage build for Spring Boot application
FROM maven:3.9-eclipse-temurin-21 AS build

# Set working directory
WORKDIR /app

# Copy pom.xml and download dependencies (for better layer caching)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

# Set working directory
WORKDIR /app

# Create a non-root user
RUN addgroup -g 1001 -S appuser && adduser -u 1001 -S appuser -G appuser

# Copy the built jar from the build stage
COPY --from=build /app/target/shopping-cart-*.jar app.jar

# Change ownership of the app directory to the appuser
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
````

## File: init-mongo.js
````javascript
// MongoDB initialization script for shopping-cart database
db = db.getSiblingDB('shopping-cart');

// Create collections
db.createCollection('products');
db.createCollection('carts');
db.createCollection('orders');

// Insert sample data
db.products.insertMany([
    {
        _id: ObjectId(),
        name: "Laptop",
        description: "High-performance laptop",
        price: 999.99,
        category: "Electronics",
        stock: 50,
        createdAt: new Date()
    },
    {
        _id: ObjectId(),
        name: "Smartphone",
        description: "Latest smartphone model",
        price: 699.99,
        category: "Electronics",
        stock: 100,
        createdAt: new Date()
    },
    {
        _id: ObjectId(),
        name: "Coffee Mug",
        description: "Ceramic coffee mug",
        price: 15.99,
        category: "Home & Kitchen",
        stock: 200,
        createdAt: new Date()
    }
]);

print('Shopping cart database initialized successfully!');
````

## File: mvnw
````
#!/bin/sh
# ----------------------------------------------------------------------------
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Apache Maven Wrapper startup batch script, version 3.3.2
#
# Optional ENV vars
# -----------------
#   JAVA_HOME - location of a JDK home dir, required when download maven via java source
#   MVNW_REPOURL - repo url base for downloading maven distribution
#   MVNW_USERNAME/MVNW_PASSWORD - user and password for downloading maven
#   MVNW_VERBOSE - true: enable verbose log; debug: trace the mvnw script; others: silence the output
# ----------------------------------------------------------------------------

set -euf
[ "${MVNW_VERBOSE-}" != debug ] || set -x

# OS specific support.
native_path() { printf %s\\n "$1"; }
case "$(uname)" in
CYGWIN* | MINGW*)
  [ -z "${JAVA_HOME-}" ] || JAVA_HOME="$(cygpath --unix "$JAVA_HOME")"
  native_path() { cygpath --path --windows "$1"; }
  ;;
esac

# set JAVACMD and JAVACCMD
set_java_home() {
  # For Cygwin and MinGW, ensure paths are in Unix format before anything is touched
  if [ -n "${JAVA_HOME-}" ]; then
    if [ -x "$JAVA_HOME/jre/sh/java" ]; then
      # IBM's JDK on AIX uses strange locations for the executables
      JAVACMD="$JAVA_HOME/jre/sh/java"
      JAVACCMD="$JAVA_HOME/jre/sh/javac"
    else
      JAVACMD="$JAVA_HOME/bin/java"
      JAVACCMD="$JAVA_HOME/bin/javac"

      if [ ! -x "$JAVACMD" ] || [ ! -x "$JAVACCMD" ]; then
        echo "The JAVA_HOME environment variable is not defined correctly, so mvnw cannot run." >&2
        echo "JAVA_HOME is set to \"$JAVA_HOME\", but \"\$JAVA_HOME/bin/java\" or \"\$JAVA_HOME/bin/javac\" does not exist." >&2
        return 1
      fi
    fi
  else
    JAVACMD="$(
      'set' +e
      'unset' -f command 2>/dev/null
      'command' -v java
    )" || :
    JAVACCMD="$(
      'set' +e
      'unset' -f command 2>/dev/null
      'command' -v javac
    )" || :

    if [ ! -x "${JAVACMD-}" ] || [ ! -x "${JAVACCMD-}" ]; then
      echo "The java/javac command does not exist in PATH nor is JAVA_HOME set, so mvnw cannot run." >&2
      return 1
    fi
  fi
}

# hash string like Java String::hashCode
hash_string() {
  str="${1:-}" h=0
  while [ -n "$str" ]; do
    char="${str%"${str#?}"}"
    h=$(((h * 31 + $(LC_CTYPE=C printf %d "'$char")) % 4294967296))
    str="${str#?}"
  done
  printf %x\\n $h
}

verbose() { :; }
[ "${MVNW_VERBOSE-}" != true ] || verbose() { printf %s\\n "${1-}"; }

die() {
  printf %s\\n "$1" >&2
  exit 1
}

trim() {
  # MWRAPPER-139:
  #   Trims trailing and leading whitespace, carriage returns, tabs, and linefeeds.
  #   Needed for removing poorly interpreted newline sequences when running in more
  #   exotic environments such as mingw bash on Windows.
  printf "%s" "${1}" | tr -d '[:space:]'
}

# parse distributionUrl and optional distributionSha256Sum, requires .mvn/wrapper/maven-wrapper.properties
while IFS="=" read -r key value; do
  case "${key-}" in
  distributionUrl) distributionUrl=$(trim "${value-}") ;;
  distributionSha256Sum) distributionSha256Sum=$(trim "${value-}") ;;
  esac
done <"${0%/*}/.mvn/wrapper/maven-wrapper.properties"
[ -n "${distributionUrl-}" ] || die "cannot read distributionUrl property in ${0%/*}/.mvn/wrapper/maven-wrapper.properties"

case "${distributionUrl##*/}" in
maven-mvnd-*bin.*)
  MVN_CMD=mvnd.sh _MVNW_REPO_PATTERN=/maven/mvnd/
  case "${PROCESSOR_ARCHITECTURE-}${PROCESSOR_ARCHITEW6432-}:$(uname -a)" in
  *AMD64:CYGWIN* | *AMD64:MINGW*) distributionPlatform=windows-amd64 ;;
  :Darwin*x86_64) distributionPlatform=darwin-amd64 ;;
  :Darwin*arm64) distributionPlatform=darwin-aarch64 ;;
  :Linux*x86_64*) distributionPlatform=linux-amd64 ;;
  *)
    echo "Cannot detect native platform for mvnd on $(uname)-$(uname -m), use pure java version" >&2
    distributionPlatform=linux-amd64
    ;;
  esac
  distributionUrl="${distributionUrl%-bin.*}-$distributionPlatform.zip"
  ;;
maven-mvnd-*) MVN_CMD=mvnd.sh _MVNW_REPO_PATTERN=/maven/mvnd/ ;;
*) MVN_CMD="mvn${0##*/mvnw}" _MVNW_REPO_PATTERN=/org/apache/maven/ ;;
esac

# apply MVNW_REPOURL and calculate MAVEN_HOME
# maven home pattern: ~/.m2/wrapper/dists/{apache-maven-<version>,maven-mvnd-<version>-<platform>}/<hash>
[ -z "${MVNW_REPOURL-}" ] || distributionUrl="$MVNW_REPOURL$_MVNW_REPO_PATTERN${distributionUrl#*"$_MVNW_REPO_PATTERN"}"
distributionUrlName="${distributionUrl##*/}"
distributionUrlNameMain="${distributionUrlName%.*}"
distributionUrlNameMain="${distributionUrlNameMain%-bin}"
MAVEN_USER_HOME="${MAVEN_USER_HOME:-${HOME}/.m2}"
MAVEN_HOME="${MAVEN_USER_HOME}/wrapper/dists/${distributionUrlNameMain-}/$(hash_string "$distributionUrl")"

exec_maven() {
  unset MVNW_VERBOSE MVNW_USERNAME MVNW_PASSWORD MVNW_REPOURL || :
  exec "$MAVEN_HOME/bin/$MVN_CMD" "$@" || die "cannot exec $MAVEN_HOME/bin/$MVN_CMD"
}

if [ -d "$MAVEN_HOME" ]; then
  verbose "found existing MAVEN_HOME at $MAVEN_HOME"
  exec_maven "$@"
fi

case "${distributionUrl-}" in
*?-bin.zip | *?maven-mvnd-?*-?*.zip) ;;
*) die "distributionUrl is not valid, must match *-bin.zip or maven-mvnd-*.zip, but found '${distributionUrl-}'" ;;
esac

# prepare tmp dir
if TMP_DOWNLOAD_DIR="$(mktemp -d)" && [ -d "$TMP_DOWNLOAD_DIR" ]; then
  clean() { rm -rf -- "$TMP_DOWNLOAD_DIR"; }
  trap clean HUP INT TERM EXIT
else
  die "cannot create temp dir"
fi

mkdir -p -- "${MAVEN_HOME%/*}"

# Download and Install Apache Maven
verbose "Couldn't find MAVEN_HOME, downloading and installing it ..."
verbose "Downloading from: $distributionUrl"
verbose "Downloading to: $TMP_DOWNLOAD_DIR/$distributionUrlName"

# select .zip or .tar.gz
if ! command -v unzip >/dev/null; then
  distributionUrl="${distributionUrl%.zip}.tar.gz"
  distributionUrlName="${distributionUrl##*/}"
fi

# verbose opt
__MVNW_QUIET_WGET=--quiet __MVNW_QUIET_CURL=--silent __MVNW_QUIET_UNZIP=-q __MVNW_QUIET_TAR=''
[ "${MVNW_VERBOSE-}" != true ] || __MVNW_QUIET_WGET='' __MVNW_QUIET_CURL='' __MVNW_QUIET_UNZIP='' __MVNW_QUIET_TAR=v

# normalize http auth
case "${MVNW_PASSWORD:+has-password}" in
'') MVNW_USERNAME='' MVNW_PASSWORD='' ;;
has-password) [ -n "${MVNW_USERNAME-}" ] || MVNW_USERNAME='' MVNW_PASSWORD='' ;;
esac

if [ -z "${MVNW_USERNAME-}" ] && command -v wget >/dev/null; then
  verbose "Found wget ... using wget"
  wget ${__MVNW_QUIET_WGET:+"$__MVNW_QUIET_WGET"} "$distributionUrl" -O "$TMP_DOWNLOAD_DIR/$distributionUrlName" || die "wget: Failed to fetch $distributionUrl"
elif [ -z "${MVNW_USERNAME-}" ] && command -v curl >/dev/null; then
  verbose "Found curl ... using curl"
  curl ${__MVNW_QUIET_CURL:+"$__MVNW_QUIET_CURL"} -f -L -o "$TMP_DOWNLOAD_DIR/$distributionUrlName" "$distributionUrl" || die "curl: Failed to fetch $distributionUrl"
elif set_java_home; then
  verbose "Falling back to use Java to download"
  javaSource="$TMP_DOWNLOAD_DIR/Downloader.java"
  targetZip="$TMP_DOWNLOAD_DIR/$distributionUrlName"
  cat >"$javaSource" <<-END
	public class Downloader extends java.net.Authenticator
	{
	  protected java.net.PasswordAuthentication getPasswordAuthentication()
	  {
	    return new java.net.PasswordAuthentication( System.getenv( "MVNW_USERNAME" ), System.getenv( "MVNW_PASSWORD" ).toCharArray() );
	  }
	  public static void main( String[] args ) throws Exception
	  {
	    setDefault( new Downloader() );
	    java.nio.file.Files.copy( java.net.URI.create( args[0] ).toURL().openStream(), java.nio.file.Paths.get( args[1] ).toAbsolutePath().normalize() );
	  }
	}
	END
  # For Cygwin/MinGW, switch paths to Windows format before running javac and java
  verbose " - Compiling Downloader.java ..."
  "$(native_path "$JAVACCMD")" "$(native_path "$javaSource")" || die "Failed to compile Downloader.java"
  verbose " - Running Downloader.java ..."
  "$(native_path "$JAVACMD")" -cp "$(native_path "$TMP_DOWNLOAD_DIR")" Downloader "$distributionUrl" "$(native_path "$targetZip")"
fi

# If specified, validate the SHA-256 sum of the Maven distribution zip file
if [ -n "${distributionSha256Sum-}" ]; then
  distributionSha256Result=false
  if [ "$MVN_CMD" = mvnd.sh ]; then
    echo "Checksum validation is not supported for maven-mvnd." >&2
    echo "Please disable validation by removing 'distributionSha256Sum' from your maven-wrapper.properties." >&2
    exit 1
  elif command -v sha256sum >/dev/null; then
    if echo "$distributionSha256Sum  $TMP_DOWNLOAD_DIR/$distributionUrlName" | sha256sum -c >/dev/null 2>&1; then
      distributionSha256Result=true
    fi
  elif command -v shasum >/dev/null; then
    if echo "$distributionSha256Sum  $TMP_DOWNLOAD_DIR/$distributionUrlName" | shasum -a 256 -c >/dev/null 2>&1; then
      distributionSha256Result=true
    fi
  else
    echo "Checksum validation was requested but neither 'sha256sum' or 'shasum' are available." >&2
    echo "Please install either command, or disable validation by removing 'distributionSha256Sum' from your maven-wrapper.properties." >&2
    exit 1
  fi
  if [ $distributionSha256Result = false ]; then
    echo "Error: Failed to validate Maven distribution SHA-256, your Maven distribution might be compromised." >&2
    echo "If you updated your Maven version, you need to update the specified distributionSha256Sum property." >&2
    exit 1
  fi
fi

# unzip and move
if command -v unzip >/dev/null; then
  unzip ${__MVNW_QUIET_UNZIP:+"$__MVNW_QUIET_UNZIP"} "$TMP_DOWNLOAD_DIR/$distributionUrlName" -d "$TMP_DOWNLOAD_DIR" || die "failed to unzip"
else
  tar xzf${__MVNW_QUIET_TAR:+"$__MVNW_QUIET_TAR"} "$TMP_DOWNLOAD_DIR/$distributionUrlName" -C "$TMP_DOWNLOAD_DIR" || die "failed to untar"
fi
printf %s\\n "$distributionUrl" >"$TMP_DOWNLOAD_DIR/$distributionUrlNameMain/mvnw.url"
mv -- "$TMP_DOWNLOAD_DIR/$distributionUrlNameMain" "$MAVEN_HOME" || [ -d "$MAVEN_HOME" ] || die "fail to move MAVEN_HOME"

clean || :
exec_maven "$@"
````

## File: mvnw.cmd
````
<# : batch portion
@REM ----------------------------------------------------------------------------
@REM Licensed to the Apache Software Foundation (ASF) under one
@REM or more contributor license agreements.  See the NOTICE file
@REM distributed with this work for additional information
@REM regarding copyright ownership.  The ASF licenses this file
@REM to you under the Apache License, Version 2.0 (the
@REM "License"); you may not use this file except in compliance
@REM with the License.  You may obtain a copy of the License at
@REM
@REM    http://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing,
@REM software distributed under the License is distributed on an
@REM "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
@REM KIND, either express or implied.  See the License for the
@REM specific language governing permissions and limitations
@REM under the License.
@REM ----------------------------------------------------------------------------

@REM ----------------------------------------------------------------------------
@REM Apache Maven Wrapper startup batch script, version 3.3.2
@REM
@REM Optional ENV vars
@REM   MVNW_REPOURL - repo url base for downloading maven distribution
@REM   MVNW_USERNAME/MVNW_PASSWORD - user and password for downloading maven
@REM   MVNW_VERBOSE - true: enable verbose log; others: silence the output
@REM ----------------------------------------------------------------------------

@IF "%__MVNW_ARG0_NAME__%"=="" (SET __MVNW_ARG0_NAME__=%~nx0)
@SET __MVNW_CMD__=
@SET __MVNW_ERROR__=
@SET __MVNW_PSMODULEP_SAVE=%PSModulePath%
@SET PSModulePath=
@FOR /F "usebackq tokens=1* delims==" %%A IN (`powershell -noprofile "& {$scriptDir='%~dp0'; $script='%__MVNW_ARG0_NAME__%'; icm -ScriptBlock ([Scriptblock]::Create((Get-Content -Raw '%~f0'))) -NoNewScope}"`) DO @(
  IF "%%A"=="MVN_CMD" (set __MVNW_CMD__=%%B) ELSE IF "%%B"=="" (echo %%A) ELSE (echo %%A=%%B)
)
@SET PSModulePath=%__MVNW_PSMODULEP_SAVE%
@SET __MVNW_PSMODULEP_SAVE=
@SET __MVNW_ARG0_NAME__=
@SET MVNW_USERNAME=
@SET MVNW_PASSWORD=
@IF NOT "%__MVNW_CMD__%"=="" (%__MVNW_CMD__% %*)
@echo Cannot start maven from wrapper >&2 && exit /b 1
@GOTO :EOF
: end batch / begin powershell #>

$ErrorActionPreference = "Stop"
if ($env:MVNW_VERBOSE -eq "true") {
  $VerbosePreference = "Continue"
}

# calculate distributionUrl, requires .mvn/wrapper/maven-wrapper.properties
$distributionUrl = (Get-Content -Raw "$scriptDir/.mvn/wrapper/maven-wrapper.properties" | ConvertFrom-StringData).distributionUrl
if (!$distributionUrl) {
  Write-Error "cannot read distributionUrl property in $scriptDir/.mvn/wrapper/maven-wrapper.properties"
}

switch -wildcard -casesensitive ( $($distributionUrl -replace '^.*/','') ) {
  "maven-mvnd-*" {
    $USE_MVND = $true
    $distributionUrl = $distributionUrl -replace '-bin\.[^.]*$',"-windows-amd64.zip"
    $MVN_CMD = "mvnd.cmd"
    break
  }
  default {
    $USE_MVND = $false
    $MVN_CMD = $script -replace '^mvnw','mvn'
    break
  }
}

# apply MVNW_REPOURL and calculate MAVEN_HOME
# maven home pattern: ~/.m2/wrapper/dists/{apache-maven-<version>,maven-mvnd-<version>-<platform>}/<hash>
if ($env:MVNW_REPOURL) {
  $MVNW_REPO_PATTERN = if ($USE_MVND) { "/org/apache/maven/" } else { "/maven/mvnd/" }
  $distributionUrl = "$env:MVNW_REPOURL$MVNW_REPO_PATTERN$($distributionUrl -replace '^.*'+$MVNW_REPO_PATTERN,'')"
}
$distributionUrlName = $distributionUrl -replace '^.*/',''
$distributionUrlNameMain = $distributionUrlName -replace '\.[^.]*$','' -replace '-bin$',''
$MAVEN_HOME_PARENT = "$HOME/.m2/wrapper/dists/$distributionUrlNameMain"
if ($env:MAVEN_USER_HOME) {
  $MAVEN_HOME_PARENT = "$env:MAVEN_USER_HOME/wrapper/dists/$distributionUrlNameMain"
}
$MAVEN_HOME_NAME = ([System.Security.Cryptography.MD5]::Create().ComputeHash([byte[]][char[]]$distributionUrl) | ForEach-Object {$_.ToString("x2")}) -join ''
$MAVEN_HOME = "$MAVEN_HOME_PARENT/$MAVEN_HOME_NAME"

if (Test-Path -Path "$MAVEN_HOME" -PathType Container) {
  Write-Verbose "found existing MAVEN_HOME at $MAVEN_HOME"
  Write-Output "MVN_CMD=$MAVEN_HOME/bin/$MVN_CMD"
  exit $?
}

if (! $distributionUrlNameMain -or ($distributionUrlName -eq $distributionUrlNameMain)) {
  Write-Error "distributionUrl is not valid, must end with *-bin.zip, but found $distributionUrl"
}

# prepare tmp dir
$TMP_DOWNLOAD_DIR_HOLDER = New-TemporaryFile
$TMP_DOWNLOAD_DIR = New-Item -Itemtype Directory -Path "$TMP_DOWNLOAD_DIR_HOLDER.dir"
$TMP_DOWNLOAD_DIR_HOLDER.Delete() | Out-Null
trap {
  if ($TMP_DOWNLOAD_DIR.Exists) {
    try { Remove-Item $TMP_DOWNLOAD_DIR -Recurse -Force | Out-Null }
    catch { Write-Warning "Cannot remove $TMP_DOWNLOAD_DIR" }
  }
}

New-Item -Itemtype Directory -Path "$MAVEN_HOME_PARENT" -Force | Out-Null

# Download and Install Apache Maven
Write-Verbose "Couldn't find MAVEN_HOME, downloading and installing it ..."
Write-Verbose "Downloading from: $distributionUrl"
Write-Verbose "Downloading to: $TMP_DOWNLOAD_DIR/$distributionUrlName"

$webclient = New-Object System.Net.WebClient
if ($env:MVNW_USERNAME -and $env:MVNW_PASSWORD) {
  $webclient.Credentials = New-Object System.Net.NetworkCredential($env:MVNW_USERNAME, $env:MVNW_PASSWORD)
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$webclient.DownloadFile($distributionUrl, "$TMP_DOWNLOAD_DIR/$distributionUrlName") | Out-Null

# If specified, validate the SHA-256 sum of the Maven distribution zip file
$distributionSha256Sum = (Get-Content -Raw "$scriptDir/.mvn/wrapper/maven-wrapper.properties" | ConvertFrom-StringData).distributionSha256Sum
if ($distributionSha256Sum) {
  if ($USE_MVND) {
    Write-Error "Checksum validation is not supported for maven-mvnd. `nPlease disable validation by removing 'distributionSha256Sum' from your maven-wrapper.properties."
  }
  Import-Module $PSHOME\Modules\Microsoft.PowerShell.Utility -Function Get-FileHash
  if ((Get-FileHash "$TMP_DOWNLOAD_DIR/$distributionUrlName" -Algorithm SHA256).Hash.ToLower() -ne $distributionSha256Sum) {
    Write-Error "Error: Failed to validate Maven distribution SHA-256, your Maven distribution might be compromised. If you updated your Maven version, you need to update the specified distributionSha256Sum property."
  }
}

# unzip and move
Expand-Archive "$TMP_DOWNLOAD_DIR/$distributionUrlName" -DestinationPath "$TMP_DOWNLOAD_DIR" | Out-Null
Rename-Item -Path "$TMP_DOWNLOAD_DIR/$distributionUrlNameMain" -NewName $MAVEN_HOME_NAME | Out-Null
try {
  Move-Item -Path "$TMP_DOWNLOAD_DIR/$MAVEN_HOME_NAME" -Destination $MAVEN_HOME_PARENT | Out-Null
} catch {
  if (! (Test-Path -Path "$MAVEN_HOME" -PathType Container)) {
    Write-Error "fail to move MAVEN_HOME"
  }
} finally {
  try { Remove-Item $TMP_DOWNLOAD_DIR -Recurse -Force | Out-Null }
  catch { Write-Warning "Cannot remove $TMP_DOWNLOAD_DIR" }
}

Write-Output "MVN_CMD=$MAVEN_HOME/bin/$MVN_CMD"
````

## File: pom.xml
````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.5.3</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>pk.ai</groupId>
	<artifactId>shopping-cart</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>shopping-cart</name>
	<description>shopping cart service</description>
	<url/>
	<licenses>
		<license/>
	</licenses>
	<developers>
		<developer/>
	</developers>
	<scm>
		<connection/>
		<developerConnection/>
		<tag/>
		<url/>
	</scm>
	<properties>
		<java.version>21</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-mongodb</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-actuator</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-validation</artifactId>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.11.5</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.springdoc</groupId>
			<artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
			<version>2.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.apache.maven.plugins</groupId>
				<artifactId>maven-compiler-plugin</artifactId>
				<configuration>
					<annotationProcessorPaths>
						<path>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</path>
					</annotationProcessorPaths>
				</configuration>
			</plugin>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<configuration>
					<excludes>
						<exclude>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</exclude>
					</excludes>
					<image>
						<name>shopping-cart:${project.version}</name>
						<buildpacks>
							<buildpack>paketobuildpacks/java</buildpack>
						</buildpacks>
					</image>
				</configuration>
			</plugin>
		</plugins>
	</build>

</project>
````

## File: README.md
````markdown
# Shopping Cart Service

A modern Spring Boot microservice for managing shopping cart operations, built with Java 21, Spring Boot 3.5.3, and MongoDB. This service provides a robust, scalable, and Docker-ready solution for e-commerce applications.

## Table of Contents
- [Overview](#overview)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Docker Setup](#docker-setup)
- [Development](#development)
- [Testing](#testing)
- [Monitoring](#monitoring)
- [Production Deployment](#production-deployment)
- [Contributing](#contributing)

## Overview

The Shopping Cart Service is a comprehensive e-commerce microservice built with a 3-phase architecture that provides:

### 🏗️ **Phase 1: Service Abstraction Layer**
- **Payment Gateway Integration** - Abstracted payment processing with multiple provider support
- **Notification Services** - Email, SMS, and push notification abstractions
- **Stub Implementations** - Development-ready mock services for testing
- **Configuration-Driven** - Switch between stub and real services via profiles

### 👤 **Phase 2: User Management & Authentication**
- **User Registration & Authentication** - Complete user account management
- **JWT Token Security** - Secure API access with token-based authentication
- **Password Encryption** - BCrypt hashing for secure password storage
- **Profile Management** - User profiles with addresses and preferences

### 🛒 **Phase 3: Shopping Cart Operations**
- **Product Catalog Management** - Complete product inventory with search and categories
- **Shopping Cart Operations** - Add, remove, update items with automatic calculations
- **Stock Management** - Real-time inventory tracking and validation
- **Cart Persistence** - MongoDB storage with expiration and cleanup

## Technology Stack

- **Java**: 21 (LTS)
- **Framework**: Spring Boot 3.5.3
- **Database**: MongoDB 7.0
- **Security**: Spring Security + JWT Authentication
- **Build Tool**: Maven 3.9+
- **Container**: Docker & Docker Compose
- **Monitoring**: Spring Boot Actuator
- **Utilities**: Lombok for boilerplate code reduction

### Dependencies
- Spring Boot Starter Web
- Spring Boot Starter Data MongoDB
- Spring Boot Starter Security
- Spring Boot Starter Validation
- Spring Boot Starter Actuator
- JWT Libraries (jjwt-api, jjwt-impl, jjwt-jackson)
- Lombok
- Spring Boot Starter Test
- OpenAPI/Swagger Documentation

## Getting Started

### Prerequisites
- Java 21 or higher
- Maven 3.9 or higher
- MongoDB 7.0 (or use Docker Compose)
- Docker & Docker Compose (optional, for containerized setup)

### Quick Start with Docker Compose (Recommended)

The easiest way to run the application with all dependencies:

```bash
# Clone the repository
git clone <repository-url>
cd shopping-cart

# Start the application and MongoDB
docker-compose up -d

# View logs
docker-compose logs -f shopping-cart-app

# Stop the application
docker-compose down
```

The application will be available at: http://localhost:8081

### Local Development Setup

1. **Start MongoDB** (if not using Docker):
   ```bash
   # Using MongoDB locally
   mongod --dbpath /path/to/your/data/directory
   ```

2. **Build the application**:
   ```bash
   mvn clean package
   ```

3. **Run the application**:
   ```bash
   # Run with local profile (recommended for development)
   SPRING_PROFILES_ACTIVE=local mvn spring-boot:run
   ```

   Or run with custom MongoDB configuration:
   ```bash
   mvn spring-boot:run -Dspring-boot.run.arguments="--spring.data.mongodb.host=localhost --spring.data.mongodb.port=27017"
   ```

4. **Initialize sample data** (optional):
   ```bash
   # Create sample products for testing
   curl -X POST http://localhost:8081/api/products/sample
   ```

## API Documentation

### Base URL
```
http://localhost:8081
```

### Security & Authentication

The application uses **JWT (JSON Web Token)** authentication for secure API access:

- **Development Environment**: Some endpoints are publicly accessible for testing
- **Production Environment**: All endpoints require proper authentication
- **Token Expiration**: JWT tokens expire after 24 hours
- **Password Security**: BCrypt encryption with 12-round strength
- **Logout Mechanism**: Server-side token blacklist for secure logout
- **Token Invalidation**: Blacklisted tokens are automatically cleaned up after expiration

### API Endpoints

#### 🔧 **System & Configuration**
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/actuator/health` | Application health status | No |
| `GET` | `/actuator/info` | Application information | No |
| `GET` | `/actuator/metrics` | Application metrics | No |
| `GET` | `/api/test/config` | Service configuration status | Dev: No |

#### 👤 **User Management** (`/api/users`)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/users/register` | Register new user account | No |
| `POST` | `/api/users/login` | Authenticate user and get JWT token | No |
| `POST` | `/api/users/logout` | Logout user and invalidate JWT token | Yes |
| `GET` | `/api/users/check-username/{username}` | Check username availability | No |
| `GET` | `/api/users/check-email/{email}` | Check email availability | No |

#### 📦 **Product Catalog** (`/api/products`)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/products` | List all available products | Dev: No |
| `GET` | `/api/products/{id}` | Get specific product details | Dev: No |
| `GET` | `/api/products/search?q={term}` | Search products by name/description | Dev: No |
| `GET` | `/api/products/category/{category}` | Get products by category | Dev: No |
| `POST` | `/api/products/sample` | Create sample products (testing) | Dev: No |

#### 🛒 **Shopping Cart** (`/api/cart`)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/cart?userId={id}` | Get user's shopping cart | Dev: No |
| `POST` | `/api/cart/items?userId={id}` | Add item to cart | Dev: No |
| `PUT` | `/api/cart/items?userId={id}` | Update item quantity | Dev: No |
| `DELETE` | `/api/cart/items/{productId}?userId={id}` | Remove item from cart | Dev: No |
| `DELETE` | `/api/cart?userId={id}` | Clear entire cart | Dev: No |

### Request/Response Examples

#### User Registration
```bash
curl -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

**Response:**
```json
{
  "id": "60d5ecb54b24a62d3c5b2b8a",
  "username": "john_doe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "status": "ACTIVE",
  "role": "USER",
  "createdAt": "2024-07-24T10:30:00Z"
}
```

#### User Login
```bash
curl -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "secure123"
  }'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9...",
  "type": "Bearer",
  "expiresIn": 86400000,
  "user": {
    "id": "60d5ecb54b24a62d3c5b2b8a",
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

#### User Logout
```bash
curl -X POST http://localhost:8081/api/users/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..."
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

#### Add Item to Cart
```bash
curl -X POST "http://localhost:8081/api/cart/items?userId=60d5ecb54b24a62d3c5b2b8a" \
  -H "Content-Type: application/json" \
  -d '{
    "productId": "60d5ecb54b24a62d3c5b2b8b",
    "quantity": 2
  }'
```

**Response:**
```json
{
  "id": "60d5ecb54b24a62d3c5b2b8c",
  "userId": "60d5ecb54b24a62d3c5b2b8a",
  "items": [
    {
      "productId": "60d5ecb54b24a62d3c5b2b8b",
      "productName": "Gaming Laptop",
      "unitPrice": 1299.99,
      "quantity": 2,
      "totalPrice": 2599.98,
      "currency": "USD"
    }
  ],
  "totalItems": 2,
  "totalPrice": 2599.98,
  "currency": "USD",
  "isEmpty": false
}
```

### Complete API Journey Example

Here's a complete user journey from registration to checkout:

```bash
#!/bin/bash
# Complete E-commerce Journey Example

BASE_URL="http://localhost:8081"

echo "🚀 Starting E-commerce Journey"

# Step 1: Register a new user
echo "👤 Step 1: User Registration"
USER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shopping_user",
    "email": "user@shop.com",
    "password": "password123",
    "firstName": "Shopping",
    "lastName": "User"
  }')
echo "User created: $USER_RESPONSE"

# Extract user ID (you would parse JSON in real implementation)
USER_ID="60d5ecb54b24a62d3c5b2b8a"  # Example ID

# Step 2: Login to get JWT token
echo "🔐 Step 2: User Login"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shopping_user",
    "password": "password123"
  }')
echo "Login response: $LOGIN_RESPONSE"

# Extract JWT token (you would parse JSON in real implementation)
JWT_TOKEN="eyJhbGciOiJIUzUxMiJ9..."  # Example token

# Step 3: Browse products
echo "📦 Step 3: Browse Product Catalog"
curl -s "$BASE_URL/api/products" | jq '.'

# Step 4: Search for specific products
echo "🔍 Step 4: Search Products"
curl -s "$BASE_URL/api/products/search?q=laptop" | jq '.'

# Step 5: Add items to cart
echo "🛒 Step 5: Add Items to Cart"
curl -s -X POST "$BASE_URL/api/cart/items?userId=$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "productId": "laptop-001",
    "quantity": 1
  }' | jq '.'

# Step 6: Add more items
echo "➕ Step 6: Add More Items"
curl -s -X POST "$BASE_URL/api/cart/items?userId=$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "productId": "phone-001",
    "quantity": 2
  }' | jq '.'

# Step 7: View cart
echo "👀 Step 7: View Shopping Cart"
curl -s "$BASE_URL/api/cart?userId=$USER_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq '.'

# Step 8: Update item quantity
echo "✏️ Step 8: Update Item Quantity"
curl -s -X PUT "$BASE_URL/api/cart/items?userId=$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "productId": "phone-001",
    "quantity": 1
  }' | jq '.'

# Step 9: Remove an item
echo "🗑️ Step 9: Remove Item from Cart"
curl -s -X DELETE "$BASE_URL/api/cart/items/laptop-001?userId=$USER_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq '.'

# Step 10: Final cart review
echo "📋 Step 10: Final Cart Review"
curl -s "$BASE_URL/api/cart?userId=$USER_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq '.'

echo "✅ E-commerce Journey Completed!"
```

### Error Handling

The API returns appropriate HTTP status codes and error messages:

- **200 OK** - Successful operation
- **201 Created** - Resource created successfully
- **400 Bad Request** - Invalid request data
- **401 Unauthorized** - Authentication required
- **403 Forbidden** - Access denied
- **404 Not Found** - Resource not found
- **409 Conflict** - Resource already exists (e.g., username taken)
- **500 Internal Server Error** - Server error

**Example Error Response:**
```json
{
  "timestamp": "2024-07-24T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed for field 'email': must be a valid email address",
  "path": "/api/users/register"
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPRING_PROFILES_ACTIVE` | - | Active profile (local, dev, prod) |
| `MONGO_HOST` | localhost | MongoDB host |
| `MONGO_PORT` | 27017 | MongoDB port |
| `MONGO_DATABASE` | shopping-cart-local | MongoDB database name |
| `JWT_SECRET` | (auto-generated) | JWT signing secret (512+ bits) |
| `JWT_EXPIRATION` | 86400000 | JWT token expiration in milliseconds |
| `JAVA_OPTS` | - | JVM options for container deployment |

### Profile-Based Configuration

#### Local Profile (`local`)
- Development-friendly settings
- Detailed logging enabled
- Some endpoints accessible without authentication
- Stub payment and notification services
- MongoDB: `shopping-cart-local` database

#### Development Profile (`dev`)
- Similar to local but with more realistic settings
- External service integrations for testing
- Enhanced security configurations

#### Production Profile (`prod`)
- Full authentication required
- Real payment and notification services
- Optimized logging and monitoring
- Production-grade security settings

### Application Properties

The application supports multiple configuration formats:

**application-local.yml:**
```yaml
spring:
  application:
    name: shopping-cart
  data:
    mongodb:
      host: localhost
      port: 27017
      database: shopping-cart-local
      
server:
  port: 8081

# Service configurations for local development
services:
  payment:
    type: stub
    config:
      success-rate: 85
      response-delay: 500
  notification:
    type: stub
    config:
      log-to-console: true

# JWT Configuration
jwt:
  secret: myVeryLongSecretKeyThatIsAtLeast512BitsForHS512Algorithm...
  expiration: 86400000 # 24 hours

# Actuator configuration
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always

# Logging configuration
logging:
  level:
    pk.ai.shopping_cart: DEBUG
    org.springframework.security: DEBUG
```

## Docker Setup

This application is fully Docker-ready with multi-stage builds and production optimizations.

### Building the Docker Image

#### Option 1: Using the build script
```bash
./build-docker.sh
```

#### Option 2: Manual Docker build
```bash
docker build -t shopping-cart:latest .
```

#### Option 3: Using Spring Boot buildpacks
```bash
mvn spring-boot:build-image
```

### Running with Docker

#### With Docker Compose (Recommended)
```bash
# Development environment
docker-compose up -d

# Production environment  
docker-compose -f docker-compose.prod.yml up -d
```

#### Standalone with external MongoDB
```bash
docker run -d \
  --name shopping-cart \
  -p 8081:8081 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e MONGO_HOST=your-mongo-host \
  -e MONGO_PORT=27017 \
  -e MONGO_DATABASE=shopping-cart \
  -e JWT_SECRET=your-production-jwt-secret \
  shopping-cart:latest
```

#### With Docker network and MongoDB container
```bash
# Create network
docker network create shopping-cart-network

# Run MongoDB
docker run -d \
  --name mongodb \
  --network shopping-cart-network \
  -p 27017:27017 \
  -e MONGO_INITDB_DATABASE=shopping-cart \
  mongo:7.0

# Run the application
docker run -d \
  --name shopping-cart-app \
  --network shopping-cart-network \
  -p 8081:8081 \
  -e MONGO_HOST=mongodb \
  -e SPRING_PROFILES_ACTIVE=local \
  shopping-cart:latest
```

### Docker Features

- **Multi-stage build**: Optimized image size using Maven build stage and Alpine JRE runtime stage
- **Non-root user**: Runs as `appuser` for security
- **Health checks**: Built-in health check using Spring Boot Actuator with `wget`
- **Layered builds**: Better Docker layer caching for faster builds
- **Production ready**: Optimized for production deployments
- **Alpine Linux**: Lightweight base image for smaller container size

## Development

### Building the Project
```bash
# Clean and compile
mvn clean compile

# Package the application
mvn clean package

# Skip tests during packaging
mvn clean package -DskipTests
```

### Running Tests
```bash
# Run all tests
mvn test

# Run tests with coverage
mvn test jacoco:report
```

### Code Quality
```bash
# Check code style (if configured)
mvn checkstyle:check

# Run static analysis (if configured)
mvn spotbugs:check
```

## Testing

### Unit Tests
The application includes unit tests for service layers and controllers. Tests are located in `src/test/java`.

### Integration Tests
Integration tests verify the interaction between components and external dependencies like MongoDB.

### Test Configuration
Test properties can be configured in `src/test/resources/application-test.properties`.

## Monitoring

The application exposes several monitoring endpoints via Spring Boot Actuator:

- **Health**: `/actuator/health` - Application health status
- **Info**: `/actuator/info` - Application information
- **Metrics**: `/actuator/metrics` - Application metrics

### Health Check Details
The health check includes:
- Application status
- MongoDB connection status
- Disk space
- System metrics

## Production Deployment

### Deployment Considerations

1. **Version Management**: Use specific version tags instead of `latest`
2. **Security**: Configure proper MongoDB credentials and authentication
3. **Resources**: Set appropriate resource limits in Docker/Kubernetes
4. **Logging**: Configure centralized log aggregation
5. **Secrets**: Use proper secrets management for sensitive configuration
6. **Monitoring**: Set up application performance monitoring (APM)
7. **Backup**: Configure MongoDB backup strategies

### Production Docker Compose Example
```yaml
services:
  shopping-cart-app:
    image: shopping-cart:1.0.0  # Use specific version
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    environment:
      - JAVA_OPTS=-Xmx256m -Xms128m -XX:+UseG1GC
      - MONGO_HOST=mongodb
      - MONGO_PORT=27017
      - MONGO_DATABASE=shopping-cart
```

### Kubernetes Deployment
For Kubernetes deployments:
1. Create ConfigMaps for configuration
2. Use Secrets for sensitive data
3. Configure resource requests and limits
4. Set up health and readiness probes
5. Configure horizontal pod autoscaling

## Contributing

### Development Guidelines
1. Follow Java coding standards
2. Write comprehensive tests
3. Update documentation for API changes
4. Use conventional commits
5. Ensure Docker builds pass

### Code Style
- Use Lombok to reduce boilerplate code
- Follow Spring Boot best practices
- Maintain consistent naming conventions
- Add appropriate logging

### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Update documentation
6. Submit a pull request

## Architecture Notes

### Package Structure
```
pk.ai.shopping_cart/
├── ShoppingCartApplication.java  # Main application class
├── controller/                   # REST controllers
│   ├── CartController.java      # Shopping cart API
│   ├── ProductController.java   # Product catalog API  
│   ├── UserController.java      # User management API
│   └── TestController.java      # System configuration API
├── service/                     # Business logic
│   ├── CartService.java         # Cart operations
│   ├── ProductService.java      # Product management
│   ├── UserService.java         # User authentication
│   ├── PaymentGateway.java      # Payment abstraction
│   └── NotificationService.java # Notification abstraction
├── repository/                  # Data access layer
│   ├── CartRepository.java      # Cart data access
│   ├── ProductRepository.java   # Product data access
│   └── UserRepository.java      # User data access
├── entity/                      # MongoDB entities
│   ├── User.java               # User entity
│   ├── Product.java            # Product entity
│   ├── Cart.java               # Cart entity
│   └── CartItem.java           # Cart item entity
├── dto/                        # Data Transfer Objects
│   ├── user/                   # User DTOs
│   ├── product/                # Product DTOs
│   └── cart/                   # Cart DTOs
├── config/                     # Configuration classes
│   ├── SecurityConfig.java     # Security configuration
│   ├── ServiceFactory.java     # Service abstraction
│   └── PasswordConfig.java     # Password encryption
├── util/                       # Utility classes
│   └── JwtTokenUtil.java       # JWT token operations
└── exception/                  # Custom exceptions
    └── CustomExceptionHandler.java
```

### Design Patterns & Architecture

#### **3-Phase Microservice Architecture**
1. **Service Abstraction Layer** - Pluggable external services
2. **User Management Layer** - Authentication and user operations  
3. **Business Logic Layer** - Shopping cart and product operations

#### **Key Design Patterns**
- **Repository Pattern** - Data access abstraction with MongoDB
- **Service Layer Pattern** - Business logic encapsulation
- **DTO Pattern** - Data transfer between API layers
- **Factory Pattern** - Service abstraction and dependency injection
- **Strategy Pattern** - Multiple payment/notification providers

#### **Security Architecture**
- **JWT Authentication** - Stateless token-based security
- **BCrypt Password Hashing** - Industry-standard password encryption
- **Profile-Based Security** - Different security levels per environment
- **CORS Configuration** - Cross-origin request handling

## Troubleshooting

### Common Issues

1. **MongoDB Connection Failed**
   - Check MongoDB is running
   - Verify connection string and credentials
   - Check network connectivity

2. **Application Won't Start**
   - Verify Java version (21+)
   - Check port 8080 availability
   - Review application logs

3. **Docker Build Failures**
   - Ensure Docker daemon is running
   - Check Dockerfile syntax
   - Verify base image availability

### Logs
Application logs are available at:
- Console output (development)
- Docker logs: `docker logs shopping-cart-app`
- File logs: Configure in `application.properties`

### Performance & Monitoring

#### Health Checks
The application provides comprehensive health monitoring:
- **Application Health**: `/actuator/health`
- **MongoDB Connectivity**: Included in health check
- **Custom Health Indicators**: Service availability status

#### Metrics & Monitoring  
- **Micrometer Integration**: Built-in metrics collection
- **JVM Metrics**: Memory, CPU, garbage collection
- **HTTP Metrics**: Request/response times and counts
- **Custom Business Metrics**: Cart operations, user registrations

#### Load Testing
For performance testing, use tools like:
```bash
# Apache Bench example
ab -n 1000 -c 10 http://localhost:8081/api/products

# Artillery.js example  
artillery quick --count 50 --num 5 http://localhost:8081/api/cart?userId=test

# K6 example
k6 run --vus 10 --duration 30s load-test.js
```

### Security Considerations

#### Development vs Production
- **Development**: Some endpoints open for testing convenience
- **Production**: Full JWT authentication required for all endpoints
- **API Rate Limiting**: Configure appropriate rate limits
- **HTTPS Only**: Enable TLS in production environments

#### JWT Security Best Practices
- **Secret Management**: Use strong, unique secrets (512+ bits)
- **Token Expiration**: Configure appropriate token lifetimes
- **Refresh Tokens**: Implement token refresh mechanism
- **Secure Storage**: Store tokens securely on client side

#### MongoDB Security
- **Authentication**: Enable MongoDB authentication
- **Authorization**: Use role-based access control
- **Network Security**: Bind to private networks only
- **Encryption**: Enable encryption in transit and at rest

## License

[Add your license information here]

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation
````

## File: SECURITY.md
````markdown
# Spring Security Implementation Guide

## Overview

This document describes the Spring Security implementation for the Shopping Cart application, including JWT-based authentication, endpoint security configuration, and testing procedures.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Authentication Flow](#authentication-flow)
3. [Security Configuration](#security-configuration)
4. [JWT Implementation](#jwt-implementation)
5. [Endpoint Security](#endpoint-security)
6. [Testing Guide](#testing-guide)
7. [API Examples](#api-examples)
8. [Troubleshooting](#troubleshooting)

## Security Architecture

The application implements a stateless JWT-based authentication system with the following components:

### Core Components

1. **SecurityConfiguration** - Main Spring Security configuration
2. **JwtAuthenticationFilter** - Custom filter for JWT token validation
3. **CustomUserDetailsService** - UserDetailsService implementation
4. **JwtTokenUtil** - JWT token generation and validation utility
5. **UserService** - User management and authentication logic

### Security Flow

```
Client Request → JWT Filter → Security Context → Controller → Service
     ↓              ↓              ↓              ↓          ↓
   Token          Validate       Set Auth       Process    Business
  Extract          Token        Principal      Request     Logic
```

## Authentication Flow

### 1. User Registration

```http
POST /api/users/register
Content-Type: application/json

{
  "username": "user123",
  "email": "user@example.com", 
  "password": "securePassword",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+1234567890"
}
```

**Response:**
```json
{
  "id": "user_id",
  "username": "user123",
  "email": "user@example.com",
  "status": "PENDING_VERIFICATION",
  "roles": ["USER"],
  "emailVerified": false,
  "createdAt": "2025-07-24T15:08:47.809"
}
```

### 2. User Login

```http
POST /api/users/login
Content-Type: application/json

{
  "usernameOrEmail": "user123",
  "password": "securePassword"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "user": {
    "id": "user_id",
    "username": "user123",
    "email": "user@example.com",
    "status": "PENDING_VERIFICATION",
    "roles": ["USER"]
  }
}
```

### 3. User Logout

```http
POST /api/users/logout
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

**Important Notes:**
- Logout invalidates the JWT token by adding it to a server-side blacklist
- Once logged out, the token cannot be used for authentication
- Client should remove the token from local storage after logout
- Blacklisted tokens are automatically cleaned up after expiration

### 4. Accessing Protected Resources

```http
GET /api/products
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

## Security Configuration

### SecurityConfiguration.java

The main security configuration class that defines:

- **Password Encoding**: BCrypt with default strength
- **Session Management**: Stateless (no server-side sessions)
- **CSRF Protection**: Disabled for API usage
- **Request Authorization**: Role-based access control

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/users/register").permitAll()
                .requestMatchers("/api/users/login").permitAll()
                .requestMatchers("/api/users/check-username/**").permitAll()
                .requestMatchers("/api/users/check-email/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
            );
        
        return http.build();
    }
}
```

### JwtAuthenticationFilter.java

Custom servlet filter that processes JWT tokens in incoming requests:

- Extracts JWT token from `Authorization` header
- Validates token signature and expiration
- Sets authentication context for valid tokens
- Processes requests with `Bearer` token format

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) {
        // Extract and validate JWT token
        // Set security context if valid
        // Continue filter chain
    }
}
```

### CustomUserDetailsService.java

Implements Spring Security's UserDetailsService interface:

- Loads user details from MongoDB
- Converts User entity to UserDetails
- Handles role-based authorities
- Manages account status (active, locked, expired)

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsernameOrEmail(username, username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new CustomUserPrincipal(user);
    }
}
```

## JWT Implementation

### Enhanced Token Structure

Our JWT tokens now contain comprehensive user claims for better authorization and user experience:

**JWT Header:**
```json
{
  "alg": "HS512",
  "typ": "JWT"
}
```

**Enhanced JWT Payload:**
```json
{
  "sub": "shopping_user",
  "userId": "6881ff2755541cb662ae70e32",
  "email": "user@example.com",
  "firstName": "Shopping",
  "lastName": "User",
  "roles": ["USER"],
  "status": "ACTIVE",
  "phoneNumber": "+1234567890",
  "emailVerified": true,
  "iat": 1753350420,
  "exp": 1753436820
}
```

### Claims Explanation

- **`sub`** - Subject (username) - Primary identifier
- **`userId`** - MongoDB ObjectId for database lookups
- **`email`** - User's email address for communication
- **`firstName/lastName`** - User's full name for personalization
- **`roles`** - Array of user roles for authorization (e.g., ["USER", "ADMIN"])
- **`status`** - Account status (ACTIVE, PENDING_VERIFICATION, SUSPENDED)
- **`phoneNumber`** - Contact number for notifications
- **`emailVerified`** - Boolean indicating email verification status
- **`iat`** - Issued at timestamp (Unix epoch)
- **`exp`** - Expiration timestamp (Unix epoch)

### Token Configuration

```properties
# application.properties
jwt.secret=your-secret-key-here
jwt.expiration=86400000  # 24 hours in milliseconds
```

### Enhanced JwtTokenUtil Methods

- `generateTokenWithClaims(User user)` - Creates JWT with comprehensive user claims
- `generateToken(String username)` - Creates basic JWT token (legacy)
- `validateToken(String token, String username)` - Validates token authenticity
- `getUsernameFromToken(String token)` - Extracts username from token
- `getClaimFromToken(String token, Function<Claims, T> claimsResolver)` - Extract specific claims
- `isTokenExpired(String token)` - Checks if token has expired
- `getExpirationDateFromToken(String token)` - Gets token expiry date

### JWT Token Example

When a user logs in successfully, they receive a response like:

```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9.eyJmaXJzdE5hbWUiOiJTaG9wcGluZyIsImxhc3ROYW1lIjoiVXNlciIsImVtYWlsVmVyaWZpZWQiOmZhbHNlLCJwaG9uZU51bWJlciI6IisxMjM0NTY3ODkwIiwicm9sZXMiOlsiVVNFUiJdLCJ1c2VySWQiOiI2ODgxZmYyNzU1NDFjYjY2MmFlNzBlMzIiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJzdGF0dXMiOiJQRU5ESU5HX1ZFUklGSUNBVElPTiIsInN1YiI6InNob3BwaW5nX3VzZXIiLCJpYXQiOjE3NTMzNTA0MjAsImV4cCI6MTc1MzQzNjgyMH0.gF_I3wpgpYSHuEAX9_5A4YIrpnbMuPfFy5BfeotmCn56tfmRs1BLIFnaKAJUMYBf-LjJDeBBay9JHBzbiKIGGw",
  "user": {
    "id": "6881ff2755541cb662ae70e32",
    "username": "shopping_user",
    "email": "user@example.com",
    "firstName": "Shopping",
    "lastName": "User",
    "status": "PENDING_VERIFICATION"
  }
}
```

### Token Blacklist Service

For enhanced security, the application implements a token blacklist mechanism to invalidate JWT tokens during logout:

#### Features:
- **Server-side token invalidation**: Tokens are blacklisted on logout
- **Memory-based storage**: Uses ConcurrentHashMap for thread-safe operations
- **Automatic cleanup**: Expired tokens are removed hourly via scheduled task
- **Authentication filter integration**: Blacklisted tokens are rejected during authentication

#### Implementation:
```java
@Service
public class TokenBlacklistServiceImpl implements TokenBlacklistService {
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
    
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
    
    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupExpiredTokens() {
        blacklistedTokens.removeIf(token -> jwtTokenUtil.isTokenExpired(token));
    }
}
```

#### Production Considerations:
- For distributed systems, consider using Redis or database storage
- Implement persistence for blacklist across application restarts
- Monitor blacklist size and implement size limits if needed

## Endpoint Security

### Public Endpoints (No Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/users/register` | User registration |
| `POST` | `/api/users/login` | User authentication |
| `GET` | `/api/users/check-username/{username}` | Username availability |
| `GET` | `/api/users/check-email/{email}` | Email availability |
| `GET` | `/actuator/health` | Application health check |
| `GET` | `/error` | Error handling |

### Protected Endpoints (Authentication Required)

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| `POST` | `/api/users/logout` | User logout (token invalidation) | USER |
| `GET` | `/api/products/**` | Product catalog | USER |
| `GET` | `/api/cart/**` | Shopping cart operations | USER |
| `GET` | `/api/users/{id}` | User profile access | USER |
| `PUT` | `/api/users/{id}` | Update user profile | USER (own profile) |
| `GET` | `/actuator/**` | Management endpoints | ADMIN |

### Role-Based Access Control

- **USER**: Standard user access to products and personal data
- **ADMIN**: Administrative access to management endpoints
- **MODERATOR**: Content moderation capabilities

## Testing Guide

### 1. Test Public Endpoints

```bash
# Health check
curl http://localhost:8081/actuator/health

# Username availability
curl http://localhost:8081/api/users/check-username/testuser

# User registration
curl -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "firstName": "Test",
    "lastName": "User"
  }'
```

### 2. Test Authentication

```bash
# Login and get JWT token
curl -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "testuser",
    "password": "password123"
  }'

# Expected response:
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "user": { ... }
}
```

### 3. Test Protected Endpoints

```bash
# Without token (should return 403)
curl http://localhost:8081/api/products

# With valid token (should return 200)
curl http://localhost:8081/api/products \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 4. Test Token Validation

```bash
# Test with invalid token (should return 403)
curl http://localhost:8081/api/products \
  -H "Authorization: Bearer invalid.token.here"

# Test with expired token (should return 403)
curl http://localhost:8081/api/products \
  -H "Authorization: Bearer expired.jwt.token"
```

### 5. Test Logout Functionality

```bash
# Step 1: Login to get a token
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "testuser",
    "password": "SecurePassword123!"
  }')

# Extract token (assuming response contains "accessToken" field)
TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.accessToken')

# Step 2: Use token to access protected endpoint (should work)
curl -X GET http://localhost:8081/api/products \
  -H "Authorization: Bearer $TOKEN"

# Step 3: Logout (invalidate token)
curl -X POST http://localhost:8081/api/users/logout \
  -H "Authorization: Bearer $TOKEN"

# Step 4: Try to use the same token again (should fail with 401/403)
curl -X GET http://localhost:8081/api/products \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Verify JWT Token Claims

You can decode and verify JWT token claims using various methods:

#### Using Online Tool (for testing only)
- Visit https://jwt.io
- Paste your JWT token to see the decoded payload
- Verify all user claims are present

#### Using Browser Console
```javascript
// Decode JWT payload in browser
const token = "YOUR_JWT_TOKEN_HERE";
const payload = JSON.parse(atob(token.split('.')[1]));
console.log('JWT Claims:', payload);

// Expected claims structure:
// {
//   "sub": "username",
//   "userId": "user_object_id", 
//   "email": "user@example.com",
//   "firstName": "User",
//   "lastName": "Name",
//   "roles": ["USER"],
//   "status": "ACTIVE",
//   "phoneNumber": "+1234567890",
//   "emailVerified": true,
//   "iat": 1753350420,
//   "exp": 1753436820
// }
```

#### Using Command Line (Node.js)
```bash
# Decode JWT token payload
node -e "
const token = 'YOUR_JWT_TOKEN_HERE';
const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
console.log(JSON.stringify(payload, null, 2));
"
```

## API Examples

### Complete Authentication Flow

```bash
# 1. Register a new user
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shopper",
    "email": "shopper@example.com",
    "password": "securePass123",
    "firstName": "John",
    "lastName": "Shopper",
    "phoneNumber": "+1234567890"
  }')

echo "Registration: $REGISTER_RESPONSE"

# 2. Login to get JWT token
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "shopper",
    "password": "securePass123"
  }')

echo "Login: $LOGIN_RESPONSE"

# 3. Extract JWT token (manual step for this example)
JWT_TOKEN="eyJhbGciOiJIUzUxMiJ9..."  # Copy from login response

# 4. Access protected endpoints
curl -s http://localhost:8081/api/products \
  -H "Authorization: Bearer $JWT_TOKEN"

curl -s http://localhost:8081/api/cart?userId=USER_ID \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Error Responses

#### 401 Unauthorized
```json
{
  "error": "User not found: invaliduser"
}
```

#### 403 Forbidden
```json
{
  "timestamp": "2025-07-24T09:38:10.903+00:00",
  "status": 403,
  "error": "Forbidden", 
  "path": "/api/products"
}
```

#### 400 Bad Request
```json
{
  "error": "Username already exists: testuser"
}
```

## Troubleshooting

### Common Issues

#### 1. JWT Token Not Working
- **Symptom**: 403 Forbidden even with valid token
- **Causes**: 
  - JWT filter not properly configured
  - Invalid token format
  - Token expired
- **Solutions**:
  - Verify `Authorization: Bearer <token>` format
  - Check token expiration
  - Validate JWT secret configuration

#### 2. User Authentication Fails
- **Symptom**: 401 Unauthorized on login
- **Causes**:
  - Incorrect credentials
  - User not found
  - Account status issues
- **Solutions**:
  - Verify username/email and password
  - Check user exists in database
  - Verify user status is ACTIVE or PENDING_VERIFICATION

#### 3. Spring Security Configuration Issues
- **Symptom**: All endpoints return 403
- **Causes**:
  - Security filter chain misconfiguration
  - Missing permitAll() for public endpoints
- **Solutions**:
  - Review SecurityConfiguration.java
  - Check request matcher patterns
  - Verify filter order

#### 4. Logout Not Working
- **Symptom**: Token still works after logout
- **Causes**:
  - TokenBlacklistService not properly configured
  - JWT filter not checking blacklist
  - Token not being added to blacklist
- **Solutions**:
  - Verify TokenBlacklistService bean is created
  - Check JwtAuthenticationFilter includes blacklist check
  - Ensure logout endpoint is called with correct token format
  - Review application logs for blacklist operations

#### 5. Memory Issues with Token Blacklist
- **Symptom**: Application memory usage grows over time
- **Causes**:
  - Expired tokens not being cleaned up
  - Scheduled cleanup not running
- **Solutions**:
  - Verify @EnableScheduling is configured
  - Check cleanup task logs
  - Monitor blacklist size in application metrics
  - Consider Redis-based blacklist for production

### Debug Logging

Enable debug logging for security issues:

```properties
# application.properties
logging.level.org.springframework.security=DEBUG
logging.level.pk.ai.shopping_cart.config=DEBUG
```

### Health Check

Monitor application security status:

```bash
# Basic health check
curl http://localhost:8081/actuator/health

# Detailed health info (if enabled)
curl http://localhost:8081/actuator/info
```

## Security Best Practices

### 1. Token Management
- Use HTTPS in production
- Store tokens securely on client side
- Implement token refresh mechanism
- Set appropriate expiration times

### 2. Password Security
- Enforce strong password policies
- Use BCrypt with appropriate cost factor
- Implement account lockout mechanisms
- Consider multi-factor authentication

### 3. Endpoint Protection
- Apply principle of least privilege
- Validate all inputs
- Implement rate limiting
- Log security events

### 4. Configuration Security
- Use environment variables for secrets
- Rotate JWT signing keys regularly
- Monitor for security vulnerabilities
- Keep dependencies updated

## Configuration Files

### Key Configuration Properties

```properties
# JWT Configuration
jwt.secret=${JWT_SECRET:default-secret-key}
jwt.expiration=${JWT_EXPIRATION:86400000}

# Security Headers
server.servlet.session.tracking-modes=none
spring.security.headers.frame=DENY
spring.security.headers.content-type=nosniff

# CORS Configuration (if needed)
spring.web.cors.allowed-origins=http://localhost:3000
spring.web.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
spring.web.cors.allowed-headers=*
```

## Monitoring and Metrics

Monitor security metrics through Spring Boot Actuator:

- Authentication success/failure rates
- Token validation performance
- Active user sessions
- Security events and anomalies

```bash
# Security metrics
curl http://localhost:8081/actuator/metrics/security.authentication

# HTTP request metrics
curl http://localhost:8081/actuator/metrics/http.server.requests
```

---

**Last Updated**: July 24, 2025  
**Version**: 1.0  
**Spring Boot Version**: 3.5.3  
**Spring Security Version**: 6.2.8
````

## File: settings.xml
````xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 
                              http://maven.apache.org/xsd/settings-1.0.0.xsd">
    
    <repositories>
        <repository>
            <id>central</id>
            <name>Maven Central Repository</name>
            <url>https://repo1.maven.org/maven2</url>
            <layout>default</layout>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </repository>
    </repositories>
    
    <pluginRepositories>
        <pluginRepository>
            <id>central</id>
            <name>Maven Plugin Repository</name>
            <url>https://repo1.maven.org/maven2</url>
            <layout>default</layout>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
            <releases>
                <updatePolicy>never</updatePolicy>
            </releases>
        </pluginRepository>
    </pluginRepositories>
</settings>
````

## File: test-api.sh
````bash
#!/bin/bash

# Shopping Cart E-commerce API Test Script
# Tests all Phase 1-3 functionality

BASE_URL="http://localhost:8081"
TEST_USER="testuser$(date +%s)"
TEST_EMAIL="test$(date +%s)@example.com"

echo "🛒 Shopping Cart E-commerce API Testing"
echo "========================================="

# Phase 1: Test Service Configuration
echo -e "\n📋 Phase 1: Testing Service Configuration..."

echo "✓ Getting service configuration..."
curl -s "$BASE_URL/api/test/config" || echo "❌ Config endpoint requires authentication"

# Phase 2: Test User Management  
echo -e "\n👤 Phase 2: Testing User Management..."

echo "✓ Registering new user: $TEST_USER"
USER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USER\",
    \"email\": \"$TEST_EMAIL\", 
    \"password\": \"password123\",
    \"firstName\": \"Test\",
    \"lastName\": \"User\"
  }" || echo "❌ Registration requires authentication")

echo "Response: $USER_RESPONSE"

echo "✓ Attempting login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USER\",
    \"password\": \"password123\"
  }" || echo "❌ Login requires authentication")

echo "Response: $LOGIN_RESPONSE"

# Phase 3: Test Product Catalog
echo -e "\n📦 Phase 3: Testing Product Catalog..."

echo "✓ Creating sample products..."
curl -s -X POST "$BASE_URL/api/products/sample" || echo "❌ Products endpoint requires authentication"

echo "✓ Getting all products..."
curl -s "$BASE_URL/api/products" || echo "❌ Products endpoint requires authentication"

echo "✓ Searching products..."
curl -s "$BASE_URL/api/products/search?q=laptop" || echo "❌ Search endpoint requires authentication"

# Phase 3: Test Shopping Cart
echo -e "\n🛒 Phase 3: Testing Shopping Cart..."

TEST_USER_ID="test-user-123"

echo "✓ Getting empty cart..."
curl -s "$BASE_URL/api/cart?userId=$TEST_USER_ID" || echo "❌ Cart endpoint requires authentication"

echo "✓ Adding item to cart..."
curl -s -X POST "$BASE_URL/api/cart/items?userId=$TEST_USER_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"productId\": \"test-product-1\",
    \"quantity\": 2
  }" || echo "❌ Add to cart requires authentication"

echo "✓ Getting cart with items..."
curl -s "$BASE_URL/api/cart?userId=$TEST_USER_ID" || echo "❌ Cart endpoint requires authentication"

echo -e "\n🔒 Authentication Required"
echo "All endpoints are currently secured with Spring Security default configuration."
echo "Custom security configuration needs to be properly applied for full testing."

echo -e "\n✅ Test script completed!"
echo "Note: Full testing requires security configuration to allow API access."
````
