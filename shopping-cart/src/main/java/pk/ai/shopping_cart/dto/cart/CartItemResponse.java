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
