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
