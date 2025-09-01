package pk.ai.shopping_cart.dto.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Notification response DTO containing delivery results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NotificationResponse {

    private String notificationId;
    private NotificationStatus status;
    private String channel;
    private String recipient;
    private String errorMessage;
    private String errorCode;
    private LocalDateTime sentAt;
    private LocalDateTime deliveredAt;
    private NotificationMetadata metadata;

    public enum NotificationStatus {
        SENT,
        DELIVERED,
        FAILED,
        PENDING,
        BOUNCED,
        SPAM
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class NotificationMetadata {
        private String providerMessageId;
        private String providerResponse;
        private String deliveryAttempts;
        private String costEstimate;
    }
}
