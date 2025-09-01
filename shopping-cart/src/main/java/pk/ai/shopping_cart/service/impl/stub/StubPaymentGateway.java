package pk.ai.shopping_cart.service.impl.stub;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.dto.payment.*;
import pk.ai.shopping_cart.service.abstraction.PaymentGatewayInterface;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Stub implementation of Payment Gateway for local/dev environments
 */
@Slf4j
@Service
@Profile({ "local", "dev", "test" })
public class StubPaymentGateway implements PaymentGatewayInterface {

    private final Map<String, TransactionStatusResponse> transactionStore = new HashMap<>();

    @Override
    public PaymentResponse processPayment(PaymentRequest paymentRequest) {
        log.info("Processing stub payment for amount: {} {}",
                paymentRequest.getAmount(), paymentRequest.getCurrency());

        String transactionId = UUID.randomUUID().toString();

        // Simulate different payment scenarios based on amount
        PaymentResponse.PaymentStatus status;
        String errorMessage = null;

        if (paymentRequest.getAmount().compareTo(new BigDecimal("1000")) > 0) {
            status = PaymentResponse.PaymentStatus.FAILED;
            errorMessage = "Stub: Amount exceeds limit for testing";
        } else if (paymentRequest.getAmount().compareTo(new BigDecimal("99.99")) == 0) {
            status = PaymentResponse.PaymentStatus.PENDING;
        } else {
            status = PaymentResponse.PaymentStatus.SUCCESS;
        }

        // Store transaction for status lookup
        TransactionStatusResponse transactionStatus = TransactionStatusResponse.builder()
                .transactionId(transactionId)
                .status(mapToTransactionStatus(status))
                .amount(paymentRequest.getAmount())
                .currency(paymentRequest.getCurrency())
                .paymentMethodId(paymentRequest.getPaymentMethodId())
                .createdAt(LocalDateTime.now())
                .lastUpdatedAt(LocalDateTime.now())
                .gatewayStatus("STUB_PROCESSED")
                .metadata(new TransactionStatusResponse.TransactionMetadata())
                .build();

        transactionStore.put(transactionId, transactionStatus);

        PaymentResponse response = PaymentResponse.builder()
                .transactionId(transactionId)
                .status(status)
                .amount(paymentRequest.getAmount())
                .currency(paymentRequest.getCurrency())
                .paymentMethodId(paymentRequest.getPaymentMethodId())
                .gatewayResponse("STUB_GATEWAY")
                .errorMessage(errorMessage)
                .processedAt(LocalDateTime.now())
                .metadata(PaymentResponse.PaymentMetadata.builder()
                        .gatewayTransactionId(transactionId)
                        .authorizationCode("STUB_AUTH_" + System.currentTimeMillis())
                        .riskScore("LOW")
                        .build())
                .build();

        log.info("Stub payment result: {} - {}", status, errorMessage != null ? errorMessage : "Success");
        return response;
    }

    @Override
    public RefundResponse refundPayment(RefundRequest refundRequest) {
        log.info("Processing stub refund for transaction: {}, amount: {}",
                refundRequest.getOriginalTransactionId(), refundRequest.getAmount());

        String refundId = UUID.randomUUID().toString();

        // Simulate refund processing
        RefundResponse.RefundStatus status = RefundResponse.RefundStatus.SUCCESS;

        RefundResponse response = RefundResponse.builder()
                .refundId(refundId)
                .originalTransactionId(refundRequest.getOriginalTransactionId())
                .status(status)
                .amount(refundRequest.getAmount())
                .currency(refundRequest.getCurrency())
                .gatewayResponse("STUB_GATEWAY")
                .processedAt(LocalDateTime.now())
                .metadata(RefundResponse.RefundMetadata.builder()
                        .gatewayRefundId(refundId)
                        .build())
                .build();

        log.info("Stub refund result: {} - Success", status);
        return response;
    }

    @Override
    public TransactionStatusResponse getTransactionStatus(String transactionId) {
        log.info("Getting stub transaction status for: {}", transactionId);

        TransactionStatusResponse status = transactionStore.get(transactionId);
        if (status != null) {
            return status;
        }

        // Return not found response
        return TransactionStatusResponse.builder()
                .transactionId(transactionId)
                .status(TransactionStatusResponse.TransactionStatus.FAILED)
                .gatewayStatus("NOT_FOUND")
                .metadata(new TransactionStatusResponse.TransactionMetadata())
                .build();
    }

    @Override
    public boolean validatePaymentMethod(String paymentMethodId) {
        log.info("Validating payment method in stub: {}", paymentMethodId);

        // Stub validation - accept most common payment method IDs
        return paymentMethodId != null &&
                (paymentMethodId.toLowerCase().contains("card") ||
                        paymentMethodId.toLowerCase().contains("wallet") ||
                        paymentMethodId.toLowerCase().contains("bank") ||
                        paymentMethodId.startsWith("pm_")); // Stripe-like format
    }

    @Override
    public String getGatewayType() {
        return "STUB_GATEWAY";
    }

    private TransactionStatusResponse.TransactionStatus mapToTransactionStatus(
            PaymentResponse.PaymentStatus paymentStatus) {
        switch (paymentStatus) {
            case SUCCESS:
                return TransactionStatusResponse.TransactionStatus.SUCCESS;
            case PENDING:
                return TransactionStatusResponse.TransactionStatus.PROCESSING;
            case FAILED:
            default:
                return TransactionStatusResponse.TransactionStatus.FAILED;
        }
    }
}
