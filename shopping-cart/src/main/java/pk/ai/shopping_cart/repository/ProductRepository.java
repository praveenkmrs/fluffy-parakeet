package pk.ai.shopping_cart.repository;

import pk.ai.shopping_cart.entity.Product;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for Product entity
 */
@Repository
public interface ProductRepository extends MongoRepository<Product, String> {

    /**
     * Find product by SKU
     */
    Optional<Product> findBySku(String sku);

    /**
     * Find products by category
     */
    List<Product> findByCategory(String category);

    /**
     * Find products by status
     */
    List<Product> findByStatus(Product.ProductStatus status);

    /**
     * Find available products (active and in stock)
     */
    @Query("{ 'status': 'ACTIVE', 'stockQuantity': { $gt: 0 } }")
    List<Product> findAvailableProducts();

    /**
     * Search products by name or description
     */
    @Query("{ $or: [ { 'name': { $regex: ?0, $options: 'i' } }, { 'description': { $regex: ?0, $options: 'i' } } ] }")
    List<Product> searchProducts(String searchTerm);

    /**
     * Find products by category and status
     */
    List<Product> findByCategoryAndStatus(String category, Product.ProductStatus status);

    /**
     * Check if SKU exists
     */
    boolean existsBySku(String sku);
}
