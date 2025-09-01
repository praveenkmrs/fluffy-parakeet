package pk.ai.shopping_cart.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Product entity representing items in the catalog
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Document(collection = "products")
public class Product {

    @Id
    private String id;

    @Indexed(unique = true)
    private String sku; // Stock Keeping Unit

    private String name;
    private String description;

    private BigDecimal price;
    private String currency;

    private Integer stockQuantity;
    private String category;
    private List<String> tags;

    private String imageUrl;
    private List<String> additionalImages;

    private ProductStatus status;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Product dimensions and weight
    private ProductDimensions dimensions;
    private Double weight; // in kg

    public enum ProductStatus {
        ACTIVE,
        INACTIVE,
        OUT_OF_STOCK,
        DISCONTINUED
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ProductDimensions {
        private Double length; // in cm
        private Double width; // in cm
        private Double height; // in cm
    }

    /**
     * Check if product is available for purchase
     */
    public boolean isAvailable() {
        return status == ProductStatus.ACTIVE && stockQuantity != null && stockQuantity > 0;
    }

    /**
     * Check if product has sufficient stock
     */
    public boolean hasStock(int quantity) {
        return stockQuantity != null && stockQuantity >= quantity;
    }
}
