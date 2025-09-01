package pk.ai.shopping_cart.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Payment response DTO containing payment processing results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentResponse {

    private String transactionId;
    private String orderId;
    private PaymentStatus status;
    private BigDecimal amount;
    private String currency;
    private String paymentMethodId;
    private String gatewayResponse;
    private String errorMessage;
    private String errorCode;
    private LocalDateTime processedAt;
    private PaymentMetadata metadata;

    public enum PaymentStatus {
        SUCCESS,
        FAILED,
        PENDING,
        CANCELLED,
        REQUIRES_ACTION
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PaymentMetadata {
        private String gatewayTransactionId;
        private String authorizationCode;
        private String riskScore;
    }
}
