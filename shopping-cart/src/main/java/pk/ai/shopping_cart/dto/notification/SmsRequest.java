package pk.ai.shopping_cart.dto.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SMS notification request DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SmsRequest {

    private String phoneNumber;
    private String message;
    private String countryCode;
    private SmsMetadata metadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SmsMetadata {
        private String userId;
        private String orderId;
        private String messageType;
        private String priority;
    }
}
