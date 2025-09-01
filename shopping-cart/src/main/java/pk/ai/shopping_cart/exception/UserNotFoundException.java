package pk.ai.shopping_cart.exception;

/**
 * Exception thrown when a requested user is not found
 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String identifier) {
        super("User not found: " + identifier);
    }

    public UserNotFoundException(String identifier, Throwable cause) {
        super("User not found: " + identifier, cause);
    }
}
