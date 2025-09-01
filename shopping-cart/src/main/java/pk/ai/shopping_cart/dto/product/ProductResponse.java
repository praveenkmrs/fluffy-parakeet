package pk.ai.shopping_cart.dto.product;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Response DTO for product
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProductResponse {

    private String id;
    private String sku;
    private String name;
    private String description;

    private BigDecimal price;
    private String currency;

    private Integer stockQuantity;
    private String category;
    private List<String> tags;

    private String imageUrl;
    private List<String> additionalImages;

    private String status;
    private boolean available;

    private ProductDimensionsResponse dimensions;
    private Double weight;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ProductDimensionsResponse {
        private Double length;
        private Double width;
        private Double height;
    }
}
