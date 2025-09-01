package pk.ai.shopping_cart.service;

import pk.ai.shopping_cart.entity.Product;
import pk.ai.shopping_cart.repository.ProductRepository;
import pk.ai.shopping_cart.dto.product.ProductResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for product catalog operations
 */
@Service
@Slf4j
public class ProductService {

    @Autowired
    private ProductRepository productRepository;

    /**
     * Create sample products for testing
     */
    public void createSampleProducts() {
        if (productRepository.count() == 0) {
            log.info("Creating sample products...");

            List<Product> sampleProducts = List.of(
                    Product.builder()
                            .sku("LAPTOP-001")
                            .name("Gaming Laptop")
                            .description("High-performance gaming laptop with RTX graphics")
                            .price(new BigDecimal("1299.99"))
                            .currency("USD")
                            .stockQuantity(10)
                            .category("Electronics")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/laptop.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build(),

                    Product.builder()
                            .sku("PHONE-001")
                            .name("Smartphone Pro")
                            .description("Latest smartphone with advanced camera system")
                            .price(new BigDecimal("899.99"))
                            .currency("USD")
                            .stockQuantity(25)
                            .category("Electronics")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/phone.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build(),

                    Product.builder()
                            .sku("BOOK-001")
                            .name("Programming Guide")
                            .description("Comprehensive guide to modern programming")
                            .price(new BigDecimal("49.99"))
                            .currency("USD")
                            .stockQuantity(50)
                            .category("Books")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/book.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build(),

                    Product.builder()
                            .sku("HEADPHONES-001")
                            .name("Wireless Headphones")
                            .description("Premium wireless headphones with noise cancellation")
                            .price(new BigDecimal("199.99"))
                            .currency("USD")
                            .stockQuantity(15)
                            .category("Electronics")
                            .status(Product.ProductStatus.ACTIVE)
                            .imageUrl("https://example.com/headphones.jpg")
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build());

            productRepository.saveAll(sampleProducts);
            log.info("Created {} sample products", sampleProducts.size());
        }
    }

    /**
     * Get all available products
     */
    public List<ProductResponse> getAvailableProducts() {
        List<Product> products = productRepository.findAvailableProducts();
        return products.stream()
                .map(this::convertToProductResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get product by ID
     */
    public ProductResponse getProduct(String id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found: " + id));
        return convertToProductResponse(product);
    }

    /**
     * Search products
     */
    public List<ProductResponse> searchProducts(String searchTerm) {
        List<Product> products = productRepository.searchProducts(searchTerm);
        return products.stream()
                .map(this::convertToProductResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get products by category
     */
    public List<ProductResponse> getProductsByCategory(String category) {
        List<Product> products = productRepository.findByCategoryAndStatus(category, Product.ProductStatus.ACTIVE);
        return products.stream()
                .map(this::convertToProductResponse)
                .collect(Collectors.toList());
    }

    /**
     * Convert Product entity to ProductResponse DTO
     */
    private ProductResponse convertToProductResponse(Product product) {
        ProductResponse.ProductDimensionsResponse dimensions = null;
        if (product.getDimensions() != null) {
            dimensions = ProductResponse.ProductDimensionsResponse.builder()
                    .length(product.getDimensions().getLength())
                    .width(product.getDimensions().getWidth())
                    .height(product.getDimensions().getHeight())
                    .build();
        }

        return ProductResponse.builder()
                .id(product.getId())
                .sku(product.getSku())
                .name(product.getName())
                .description(product.getDescription())
                .price(product.getPrice())
                .currency(product.getCurrency())
                .stockQuantity(product.getStockQuantity())
                .category(product.getCategory())
                .tags(product.getTags())
                .imageUrl(product.getImageUrl())
                .additionalImages(product.getAdditionalImages())
                .status(product.getStatus().toString())
                .available(product.isAvailable())
                .dimensions(dimensions)
                .weight(product.getWeight())
                .createdAt(product.getCreatedAt())
                .updatedAt(product.getUpdatedAt())
                .build();
    }
}
