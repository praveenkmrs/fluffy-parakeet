package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Transaction status response DTO for checking payment status
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransactionStatusResponse {

    private String transactionId;
    private String orderId;
    private TransactionStatus status;
    private BigDecimal amount;
    private String currency;
    private String paymentMethodId;
    private LocalDateTime createdAt;
    private LocalDateTime lastUpdatedAt;
    private String gatewayStatus;
    private TransactionMetadata metadata;

    public enum TransactionStatus {
        CREATED,
        PROCESSING,
        SUCCESS,
        FAILED,
        CANCELLED,
        REFUNDED,
        PARTIALLY_REFUNDED
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TransactionMetadata {
        private String gatewayTransactionId;
        private String authorizationCode;
        private String riskAssessment;
        private String processingTimeMs;
    }
}
