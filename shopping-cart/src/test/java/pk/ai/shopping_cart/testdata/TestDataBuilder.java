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
