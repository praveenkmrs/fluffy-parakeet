package pk.ai.shopping_cart.service.factory;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import pk.ai.shopping_cart.service.abstraction.NotificationServiceInterface;
import pk.ai.shopping_cart.service.abstraction.PaymentGatewayInterface;

import java.util.List;

/**
 * Service factory for managing service implementations based on active profiles
 * Automatically selects the appropriate implementation (stub or external)
 */
@Slf4j
@Component
public class ServiceFactory {

    private final PaymentGatewayInterface paymentGateway;
    private final NotificationServiceInterface notificationService;

    @Autowired
    public ServiceFactory(List<PaymentGatewayInterface> paymentGateways,
            List<NotificationServiceInterface> notificationServices) {

        // Select the first available payment gateway (Spring will inject based on
        // profile)
        this.paymentGateway = paymentGateways.stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No payment gateway implementation found"));

        // Select the first available notification service (Spring will inject based on
        // profile)
        this.notificationService = notificationServices.stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No notification service implementation found"));

        log.info("Service Factory initialized with:");
        log.info("  Payment Gateway: {}", paymentGateway.getGatewayType());
        log.info("  Notification Service: {}", notificationService.getServiceType());
    }

    /**
     * Get the active payment gateway implementation
     */
    public PaymentGatewayInterface getPaymentGateway() {
        return paymentGateway;
    }

    /**
     * Get the active notification service implementation
     */
    public NotificationServiceInterface getNotificationService() {
        return notificationService;
    }

    /**
     * Check if we're using stub implementations (useful for testing and
     * development)
     */
    public boolean isUsingStubServices() {
        return paymentGateway.getGatewayType().contains("STUB") ||
                notificationService.getServiceType().contains("STUB");
    }

    /**
     * Get service configuration info for debugging
     */
    public String getServiceConfiguration() {
        return String.format("Payment: %s, Notification: %s",
                paymentGateway.getGatewayType(),
                notificationService.getServiceType());
    }
}
