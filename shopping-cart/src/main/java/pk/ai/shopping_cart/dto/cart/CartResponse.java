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
