package pk.ai.shopping_cart.repository;

import pk.ai.shopping_cart.entity.Cart;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository for Cart entity
 */
@Repository
public interface CartRepository extends MongoRepository<Cart, String> {

    /**
     * Find active cart by user ID
     */
    @Query("{ 'userId': ?0, 'status': 'ACTIVE' }")
    Optional<Cart> findActiveCartByUserId(String userId);

    /**
     * Find all carts by user ID
     */
    List<Cart> findByUserId(String userId);

    /**
     * Find carts by status
     */
    List<Cart> findByStatus(Cart.CartStatus status);

    /**
     * Find expired carts for cleanup
     */
    @Query("{ 'expiresAt': { $lt: ?0 }, 'status': 'ACTIVE' }")
    List<Cart> findExpiredCarts(LocalDateTime currentTime);

    /**
     * Find abandoned carts (not updated for a while)
     */
    @Query("{ 'updatedAt': { $lt: ?0 }, 'status': 'ACTIVE' }")
    List<Cart> findAbandonedCarts(LocalDateTime cutoffTime);
}
