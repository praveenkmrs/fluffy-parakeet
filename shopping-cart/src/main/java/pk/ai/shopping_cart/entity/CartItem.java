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
