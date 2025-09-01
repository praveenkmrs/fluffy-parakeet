package pk.ai.shopping_cart.controller;

import pk.ai.shopping_cart.service.ProductService;
import pk.ai.shopping_cart.dto.product.ProductResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * REST controller for product catalog operations
 */
@RestController
@RequestMapping("/api/products")
@Slf4j
public class ProductController {

    @Autowired
    private ProductService productService;

    /**
     * Initialize sample products (for testing)
     */
    @PostMapping("/sample")
    public ResponseEntity<String> createSampleProducts() {
        log.debug("Creating sample products");
        productService.createSampleProducts();
        return ResponseEntity.ok("Sample products created");
    }

    /**
     * Get all available products
     */
    @GetMapping
    public ResponseEntity<List<ProductResponse>> getProducts() {
        log.debug("Getting all available products");
        List<ProductResponse> products = productService.getAvailableProducts();
        return ResponseEntity.ok(products);
    }

    /**
     * Get product by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ProductResponse> getProduct(@PathVariable String id) {
        log.debug("Getting product: {}", id);
        ProductResponse product = productService.getProduct(id);
        return ResponseEntity.ok(product);
    }

    /**
     * Search products
     */
    @GetMapping("/search")
    public ResponseEntity<List<ProductResponse>> searchProducts(@RequestParam String q) {
        log.debug("Searching products with term: {}", q);
        List<ProductResponse> products = productService.searchProducts(q);
        return ResponseEntity.ok(products);
    }

    /**
     * Get products by category
     */
    @GetMapping("/category/{category}")
    public ResponseEntity<List<ProductResponse>> getProductsByCategory(@PathVariable String category) {
        log.debug("Getting products for category: {}", category);
        List<ProductResponse> products = productService.getProductsByCategory(category);
        return ResponseEntity.ok(products);
    }
}
