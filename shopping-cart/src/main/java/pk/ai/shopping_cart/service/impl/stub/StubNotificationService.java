package pk.ai.shopping_cart.service.impl.stub;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.dto.notification.EmailRequest;
import pk.ai.shopping_cart.dto.notification.NotificationResponse;
import pk.ai.shopping_cart.dto.notification.SmsRequest;
import pk.ai.shopping_cart.service.abstraction.NotificationServiceInterface;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Stub implementation of Notification Service for local/dev environments
 */
@Slf4j
@Service
@Profile({ "local", "dev", "test" })
public class StubNotificationService implements NotificationServiceInterface {

    private final Map<String, NotificationResponse> notificationStore = new HashMap<>();

    @Override
    public NotificationResponse sendEmail(EmailRequest emailRequest) {
        log.info("Sending stub email to: {} with subject: {}",
                emailRequest.getRecipientEmail(), emailRequest.getSubject());

        String notificationId = UUID.randomUUID().toString();

        // Simulate email sending
        NotificationResponse response = NotificationResponse.builder()
                .notificationId(notificationId)
                .channel("EMAIL")
                .recipient(emailRequest.getRecipientEmail())
                .status(NotificationResponse.NotificationStatus.SENT)
                .sentAt(LocalDateTime.now())
                .metadata(NotificationResponse.NotificationMetadata.builder()
                        .providerMessageId("stub_email_" + System.currentTimeMillis())
                        .providerResponse("STUB_EMAIL_PROVIDER_SUCCESS")
                        .deliveryAttempts("1")
                        .costEstimate("$0.00")
                        .build())
                .build();

        // Store for status lookup
        notificationStore.put(notificationId, response);

        log.info("Stub email sent successfully with ID: {}", notificationId);
        log.debug("Email content preview: Subject: '{}', Template: {}",
                emailRequest.getSubject(),
                emailRequest.getTemplateId() != null ? emailRequest.getTemplateId() : "none");

        return response;
    }

    @Override
    public NotificationResponse sendSms(SmsRequest smsRequest) {
        log.info("Sending stub SMS to: {}", smsRequest.getPhoneNumber());

        String notificationId = UUID.randomUUID().toString();

        // Simulate SMS sending
        NotificationResponse response = NotificationResponse.builder()
                .notificationId(notificationId)
                .channel("SMS")
                .recipient(smsRequest.getPhoneNumber())
                .status(NotificationResponse.NotificationStatus.SENT)
                .sentAt(LocalDateTime.now())
                .metadata(NotificationResponse.NotificationMetadata.builder()
                        .providerMessageId("stub_sms_" + System.currentTimeMillis())
                        .providerResponse("STUB_SMS_PROVIDER_SUCCESS")
                        .deliveryAttempts("1")
                        .costEstimate("$0.05")
                        .build())
                .build();

        // Store for status lookup
        notificationStore.put(notificationId, response);

        log.info("Stub SMS sent successfully with ID: {}", notificationId);
        log.debug("SMS content preview: Message length: {} chars",
                smsRequest.getMessage() != null ? smsRequest.getMessage().length() : 0);

        return response;
    }

    @Override
    public NotificationResponse getNotificationStatus(String notificationId) {
        log.info("Getting stub notification status for: {}", notificationId);

        NotificationResponse status = notificationStore.get(notificationId);
        if (status != null) {
            return status;
        }

        // Return not found response
        return NotificationResponse.builder()
                .notificationId(notificationId)
                .status(NotificationResponse.NotificationStatus.FAILED)
                .errorMessage("Notification not found in stub")
                .metadata(NotificationResponse.NotificationMetadata.builder()
                        .providerResponse("NOT_FOUND")
                        .build())
                .build();
    }

    @Override
    public boolean validateRecipient(String recipient, String channel) {
        log.info("Validating recipient in stub: {} for channel: {}", recipient, channel);

        if (recipient == null || recipient.trim().isEmpty()) {
            return false;
        }

        switch (channel.toUpperCase()) {
            case "EMAIL":
                // Basic email validation
                return recipient.contains("@") && recipient.contains(".");
            case "SMS":
                // Basic phone number validation (allow various formats)
                return recipient.matches(".*\\d.*") && recipient.length() >= 10;
            default:
                log.warn("Unknown channel type for validation: {}", channel);
                return false;
        }
    }

    @Override
    public String getServiceType() {
        return "STUB_NOTIFICATION_SERVICE";
    }
}
