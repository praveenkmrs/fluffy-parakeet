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
