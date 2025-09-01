package pk.ai.shopping_cart.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pk.ai.shopping_cart.dto.notification.EmailRequest;
import pk.ai.shopping_cart.dto.notification.NotificationResponse;
import pk.ai.shopping_cart.dto.notification.SmsRequest;
import pk.ai.shopping_cart.dto.payment.PaymentRequest;
import pk.ai.shopping_cart.dto.payment.PaymentResponse;
import pk.ai.shopping_cart.service.factory.ServiceFactory;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

/**
 * Test controller for verifying service abstraction layer
 * This will be replaced with proper business controllers in later phases
 */
@Slf4j
@RestController
@RequestMapping("/api/test")
public class ServiceTestController {

    private final ServiceFactory serviceFactory;

    public ServiceTestController(ServiceFactory serviceFactory) {
        this.serviceFactory = serviceFactory;
    }

    @GetMapping("/config")
    public ResponseEntity<Map<String, String>> getServiceConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("paymentGateway", serviceFactory.getPaymentGateway().getGatewayType());
        config.put("notificationService", serviceFactory.getNotificationService().getServiceType());
        config.put("usingStubs", String.valueOf(serviceFactory.isUsingStubServices()));
        return ResponseEntity.ok(config);
    }

    @PostMapping("/payment")
    public ResponseEntity<PaymentResponse> testPayment(@RequestBody Map<String, Object> request) {
        log.info("Testing payment with: {}", request);

        PaymentRequest paymentRequest = PaymentRequest.builder()
                .amount(new BigDecimal(request.get("amount").toString()))
                .currency(request.getOrDefault("currency", "USD").toString())
                .paymentMethodId(request.getOrDefault("paymentMethodId", "test_card").toString())
                .build();

        PaymentResponse response = serviceFactory.getPaymentGateway().processPayment(paymentRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/email")
    public ResponseEntity<NotificationResponse> testEmail(@RequestBody Map<String, String> request) {
        log.info("Testing email with: {}", request);

        EmailRequest emailRequest = EmailRequest.builder()
                .recipientEmail(request.get("email"))
                .subject(request.getOrDefault("subject", "Test Email"))
                .templateId(request.getOrDefault("templateId", "test_template"))
                .build();

        NotificationResponse response = serviceFactory.getNotificationService().sendEmail(emailRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/sms")
    public ResponseEntity<NotificationResponse> testSms(@RequestBody Map<String, String> request) {
        log.info("Testing SMS with: {}", request);

        SmsRequest smsRequest = SmsRequest.builder()
                .phoneNumber(request.get("phoneNumber"))
                .message(request.getOrDefault("message", "Test SMS"))
                .build();

        NotificationResponse response = serviceFactory.getNotificationService().sendSms(smsRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/payment/{transactionId}/status")
    public ResponseEntity<?> getPaymentStatus(@PathVariable String transactionId) {
        log.info("Getting payment status for: {}", transactionId);

        var response = serviceFactory.getPaymentGateway().getTransactionStatus(transactionId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/notification/{notificationId}/status")
    public ResponseEntity<NotificationResponse> getNotificationStatus(@PathVariable String notificationId) {
        log.info("Getting notification status for: {}", notificationId);

        NotificationResponse response = serviceFactory.getNotificationService().getNotificationStatus(notificationId);
        return ResponseEntity.ok(response);
    }
}
