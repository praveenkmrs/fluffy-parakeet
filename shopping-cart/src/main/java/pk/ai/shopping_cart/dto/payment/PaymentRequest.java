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
