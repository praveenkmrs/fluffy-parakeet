package pk.ai.shopping_cart.exception;

/**
 * Exception thrown when a user tries to register with an email that already
 * exists
 */
public class EmailAlreadyExistsException extends RuntimeException {

    public EmailAlreadyExistsException(String email) {
        super("Email already exists: " + email);
    }

    public EmailAlreadyExistsException(String email, Throwable cause) {
        super("Email already exists: " + email, cause);
    }
}
