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
