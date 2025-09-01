package pk.ai.shopping_cart.service.abstraction;

import pk.ai.shopping_cart.dto.payment.PaymentRequest;
import pk.ai.shopping_cart.dto.payment.PaymentResponse;
import pk.ai.shopping_cart.dto.payment.RefundRequest;
import pk.ai.shopping_cart.dto.payment.RefundResponse;
import pk.ai.shopping_cart.dto.payment.TransactionStatusResponse;

/**
 * Payment Gateway abstraction interface
 * Allows switching between stub and external payment implementations
 */
public interface PaymentGatewayInterface {

    /**
     * Process a payment transaction
     */
    PaymentResponse processPayment(PaymentRequest paymentRequest);

    /**
     * Validate an existing payment transaction
     */
    TransactionStatusResponse getTransactionStatus(String transactionId);

    /**
     * Process a refund for a transaction
     */
    RefundResponse refundPayment(RefundRequest refundRequest);

    /**
     * Validate payment method details
     */
    boolean validatePaymentMethod(String paymentMethodId);

    /**
     * Get gateway type identifier
     */
    String getGatewayType();
}
