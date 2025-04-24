package auth_with_h2.auth_experiment.service;

import auth_with_h2.auth_experiment.entity.PasswordResetToken;
import auth_with_h2.auth_experiment.entity.User;// Assuming a custom exception or use existing
import auth_with_h2.auth_experiment.exception.InvalidTokenException;
import auth_with_h2.auth_experiment.exception.UserNotFoundException;
import auth_with_h2.auth_experiment.repository.PasswordResetTokenRepository;
import auth_with_h2.auth_experiment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class PasswordResetService {

    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    // In a real app, inject an EmailService here
    // @Autowired
    // private EmailService emailService;

    @Transactional
    public void createPasswordResetTokenForUser(String email) {
        User user = userRepository.findByEmail(email) // Assuming findByEmail exists in UserRepository
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));

        // Delete any existing token for this user before creating a new one
        tokenRepository.findByUser(user).ifPresent(tokenRepository::delete);

        String token = UUID.randomUUID().toString();
        PasswordResetToken myToken = new PasswordResetToken(token, user);
        tokenRepository.save(myToken);

        // --- Placeholder for sending email ---
        // In a real application, you would construct the reset URL and send it
        String resetUrl = "http://yourfrontend.com/reset-password?token=" + token; // Example URL
        logger.info("Password Reset Requested for {}. Send email with token {} and URL: {}",
                    user.getEmail(), token, resetUrl);
        // emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
        // ------------------------------------
    }

    /**
     * Validates the password reset token.
     * @param token The token string.
     * @return The PasswordResetToken entity if valid.
     * @throws InvalidTokenException if the token is not found or expired.
     */
    public PasswordResetToken validatePasswordResetToken(String token) {
        PasswordResetToken passToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid password reset token"));

        if (passToken.isExpired()) {
            tokenRepository.delete(passToken); // Clean up expired token
            throw new InvalidTokenException("Expired password reset token");
        }

        return passToken;
    }

    /**
     * Resets the user's password based on a valid token.
     * @param token The valid password reset token string.
     * @param newPassword The new raw password.
     * @throws InvalidTokenException if the token is invalid or expired.
     */
    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken passToken = validatePasswordResetToken(token); // Reuse validation logic
        User user = passToken.getUser();

        // Encode and set the new password
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user); // Save the updated user

        // Delete the used token
        tokenRepository.delete(passToken);

        logger.info("Password successfully reset for user: {}", user.getUsername());
        // Optionally send a confirmation email here
    }
}

// Define UserNotFoundException if it doesn't exist
// Alternatively, handle Optional in the controller or use a generic RuntimeException
// Example:
// package auth_with_h2.auth_experiment.exception;
// import org.springframework.http.HttpStatus;
// import org.springframework.web.bind.annotation.ResponseStatus;
//
// @ResponseStatus(HttpStatus.NOT_FOUND)
// public class UserNotFoundException extends RuntimeException {
//     public UserNotFoundException(String message) {
//         super(message);
//     }
// }

// Example for InvalidTokenException:
// package auth_with_h2.auth_experiment.exception;
// import org.springframework.http.HttpStatus;
// import org.springframework.web.bind.annotation.ResponseStatus;
//
// @ResponseStatus(HttpStatus.BAD_REQUEST)
// public class InvalidTokenException extends RuntimeException {
//     public InvalidTokenException(String message) {
//         super(message);
//     }
// }
