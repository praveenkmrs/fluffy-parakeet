package pk.ai.shopping_cart.dto.notification;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Email notification request DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailRequest {

    private String recipientEmail;
    private String recipientName;
    private String subject;
    private String templateId;
    private Map<String, Object> templateData;
    private EmailMetadata metadata;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EmailMetadata {
        private String userId;
        private String orderId;
        private String priority;
        private String category;
    }
}
