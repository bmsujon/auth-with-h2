package auth_with_h2.auth_experiment.exception; // Ensure package matches existing exceptions

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND) // Default response status if not handled by @ExceptionHandler
public class UserNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L; // Optional but good practice for RuntimeExceptions

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}