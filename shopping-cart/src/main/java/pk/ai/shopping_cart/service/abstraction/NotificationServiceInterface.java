package pk.ai.shopping_cart.service.abstraction;

import pk.ai.shopping_cart.dto.notification.EmailRequest;
import pk.ai.shopping_cart.dto.notification.SmsRequest;
import pk.ai.shopping_cart.dto.notification.NotificationResponse;

/**
 * Notification Service abstraction interface
 * Allows switching between stub and external notification implementations
 */
public interface NotificationServiceInterface {

    /**
     * Send email notification
     */
    NotificationResponse sendEmail(EmailRequest emailRequest);

    /**
     * Send SMS notification
     */
    NotificationResponse sendSms(SmsRequest smsRequest);

    /**
     * Get notification delivery status
     */
    NotificationResponse getNotificationStatus(String notificationId);

    /**
     * Validate notification recipient
     */
    boolean validateRecipient(String recipient, String channel);

    /**
     * Get service type identifier
     */
    String getServiceType();
}
