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
