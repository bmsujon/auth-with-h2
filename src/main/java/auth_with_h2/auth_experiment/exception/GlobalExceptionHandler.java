package auth_with_h2.auth_experiment.exception;

import auth_with_h2.auth_experiment.dto.MessageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(value = TokenRefreshException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN) // Keep the status code mapping
    public MessageResponse handleTokenRefreshException(TokenRefreshException ex, WebRequest request) {
        logger.error("Token Refresh Error: {} on path {}", ex.getMessage(), request.getDescription(false));
        return new MessageResponse(ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public MessageResponse handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
        String errors = ex.getBindingResult().getFieldErrors().stream()
                         .map(error -> error.getField() + ": " + error.getDefaultMessage())
                         .collect(Collectors.joining(", "));
        String errorMessage = "Validation failed: " + errors;
        logger.warn("Validation Error: {} on path {}", errorMessage, request.getDescription(false));
        return new MessageResponse(errorMessage);
    }
    
    @ExceptionHandler(value = UserNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public MessageResponse handleUserNotFoundException(UserNotFoundException ex, WebRequest request) {
        logger.warn("Resource Not Found: {} on path {}", ex.getMessage(), request.getDescription(false));
        return new MessageResponse(ex.getMessage());
    }
    
    @ExceptionHandler(value = InvalidTokenException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public MessageResponse handleInvalidTokenException(InvalidTokenException ex, WebRequest request) {
        logger.warn("Invalid Token Attempt: {} on path {}", ex.getMessage(), request.getDescription(false));
        return new MessageResponse(ex.getMessage());
    }
    
    // Catch-all for other RuntimeExceptions (like the Role not found one)
    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public MessageResponse handleGenericRuntimeException(RuntimeException ex, WebRequest request) {
        if (!(ex instanceof UserNotFoundException || ex instanceof InvalidTokenException || ex instanceof TokenRefreshException)) {
            logger.error("Unexpected RuntimeException: {} on path {}", ex.getMessage(), request.getDescription(false), ex); // Log stack trace for unexpected errors
        }
        // Avoid exposing internal details to the client in production
        return new MessageResponse("An unexpected internal error occurred."); 
    }


    // Optional: Catch-all for any exception if needed, but often RuntimeException is sufficient
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public MessageResponse handleGenericException(Exception ex, WebRequest request) {
        if (!(ex instanceof UserNotFoundException || ex instanceof InvalidTokenException || ex instanceof TokenRefreshException)) {
            logger.error("Unexpected Exception: {} on path {}", ex.getMessage(), request.getDescription(false), ex);
        }
        return new MessageResponse("An unexpected error occurred.");
    }
}
