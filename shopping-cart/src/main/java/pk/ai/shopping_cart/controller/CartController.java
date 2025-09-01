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
