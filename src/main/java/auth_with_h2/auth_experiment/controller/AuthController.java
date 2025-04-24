package auth_with_h2.auth_experiment.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import auth_with_h2.auth_experiment.dto.*;
import auth_with_h2.auth_experiment.enums.ERole;
import auth_with_h2.auth_experiment.exception.TokenRefreshException;
import auth_with_h2.auth_experiment.exception.UserNotFoundException;
import auth_with_h2.auth_experiment.exception.InvalidTokenException;
import auth_with_h2.auth_experiment.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException; // Import needed for 401 description
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

// Adjusted package names
import auth_with_h2.auth_experiment.entity.Role;
import auth_with_h2.auth_experiment.entity.User;
import auth_with_h2.auth_experiment.entity.RefreshToken;
import auth_with_h2.auth_experiment.repository.RoleRepository;
import auth_with_h2.auth_experiment.repository.UserRepository;
import auth_with_h2.auth_experiment.service.UserDetailsImpl; // Adjusted package
import auth_with_h2.auth_experiment.service.RefreshTokenService; // Adjusted package
import auth_with_h2.auth_experiment.service.PasswordResetService; // Service for password reset

@Tag(name = "Authentication API", description = "API endpoints for user authentication and authorization")
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    PasswordResetService passwordResetService;

    @Operation(summary = "Sign in user", description = "Authenticates a user with username and password, returning JWT and refresh tokens upon success.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Authentication successful",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = JwtResponse.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Invalid input format (e.g., missing fields)",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid credentials", // Spring Security's BadCredentialsException
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))) // Often handled by Spring Security filter chain before controller advice
    })
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication); // Generate JWT using Authentication

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
                userDetails.getUsername(), userDetails.getEmail(), roles));
    }

    @Operation(summary = "Register a new user", description = "Creates a new user account with the provided username, email, password, and optional roles. Defaults to ROLE_OTHERS if no roles specified.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User registered successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Invalid input (validation error) or username/email already exists",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "500", description = "Internal Server Error - Role not found (indicates configuration issue)",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        // --- Role assignment logic remains the same ---
        if (strRoles == null || strRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(ERole.ROLE_OTHERS) // Default role
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role.toLowerCase()) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "app_group":
                        Role appGroupRole = roleRepository.findByName(ERole.ROLE_APP_GROUP)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(appGroupRole);
                        break;
                    case "kpc":
                        Role kpcRole = roleRepository.findByName(ERole.ROLE_KPC)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(kpcRole);
                        break;
                    default:
                        Role otherRole = roleRepository.findByName(ERole.ROLE_OTHERS)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(otherRole);
                }
            });
        }
        // --- End of role assignment logic ---

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @Operation(summary = "Refresh JWT token", description = "Generates a new JWT access token using a valid refresh token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = TokenRefreshResponse.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Invalid input format",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "403", description = "Forbidden - Invalid or expired refresh token", // Matches TokenRefreshException status
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    @Operation(summary = "Get current user details", description = "Retrieves the profile information of the currently authenticated user.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully retrieved user details",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = UserInfoResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class)))
    })
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return ResponseEntity.ok(new UserInfoResponse(
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        ));
    }

    @Operation(summary = "Validate JWT token", description = "Checks if the current user's JWT token provided in the Authorization header is valid.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token is valid",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid, expired, or missing JWT",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))) // Handled by Security Filter Chain
    })
    @GetMapping("/validate")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> validateToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        return ResponseEntity.ok(new MessageResponse("Token is valid for user: " + username));
    }

    // --- Existing documented endpoints (/signout, /forgot-password, /reset-password, /change-password) remain the same ---
    // ... (keep the existing methods with their documentation here) ...

    @Operation(summary = "Sign out user", description = "Logs out the current user by deleting their refresh token.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Sign out successful",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "500", description = "Internal Server Error",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/signout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logoutUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof UserDetailsImpl)) {
            // This check might be redundant due to @PreAuthorize, but adds clarity
            return ResponseEntity.status(401).body(new MessageResponse("Error: User not authenticated"));
        }

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Long userId = userDetails.getId();

        try {
            int deletedCount = refreshTokenService.deleteByUserId(userId);
            log.info("User ID {} signed out. {} refresh tokens deleted.", userId, deletedCount);
            return ResponseEntity.ok(new MessageResponse("Log out successful!"));
        } catch (Exception e) {
            log.error("Error during sign out for user ID {}: {}", userId, e.getMessage(), e);
            // Consider if a more specific exception/handling is needed
            return ResponseEntity.status(500).body(new MessageResponse("Error: Could not process sign out request."));
        }
    }

    @Operation(summary = "Request password reset", description = "Initiates the password reset process for a user based on their email address. If the email exists, a reset token is generated and an email is intended to be sent (email sending is currently placeholder).")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset request received. If the email address is valid, a reset link will be sent.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Invalid request format (e.g., invalid email)",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class)))
            // Note: We intentionally return 200 even if email not found to prevent email enumeration attacks
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest) {
        try {
            passwordResetService.createPasswordResetTokenForUser(forgotPasswordRequest.getEmail());
        } catch (UserNotFoundException e) { // Catch the specific exception
            // Log maybe, but don't expose the error to the client
            log.warn("Password reset requested for potentially non-existent email: {}", forgotPasswordRequest.getEmail());
        } catch (Exception e) {
            log.error("Error processing forgot password request for email: {}", forgotPasswordRequest.getEmail(), e);
            // Still return a generic success message to avoid leaking information
        }
        // Always return generic 200 OK for /forgot-password
        return ResponseEntity.ok(new MessageResponse("If your email address is in our system, you will receive a password reset link shortly."));
    }

    @Operation(summary = "Reset user password", description = "Sets a new password for the user associated with the provided valid reset token.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password has been reset successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Invalid/expired token or invalid new password format",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))) // Handled by GlobalExceptionHandler for InvalidTokenException or validation
    })
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        // Service method handles validation (throws InvalidTokenException if invalid/expired)
        // and password update. GlobalExceptionHandler handles the InvalidTokenException.
        passwordResetService.resetPassword(resetPasswordRequest.getToken(), resetPasswordRequest.getNewPassword());

        return ResponseEntity.ok(new MessageResponse("Password has been reset successfully."));
    }

    @Operation(summary = "Change current user's password", description = "Allows an authenticated user to change their password by providing the current and new password. Invalidates existing refresh tokens upon success.",
            security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "400", description = "Bad Request - Incorrect current password, new password format invalid, or new password is same as old",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))), // Handled by Security Filter Chain
            @ApiResponse(responseCode = "404", description = "User not found (shouldn't happen if authenticated, but handled defensively)",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class))), // Handled by GlobalExceptionHandler
            @ApiResponse(responseCode = "500", description = "Internal Server Error - Error during token invalidation or other unexpected issue",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = MessageResponse.class)))
    })
    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    @Transactional
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest changePasswordRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Long userId = userDetails.getId();

        User currentUser = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("Authenticated user not found in database with ID: " + userId)); // Should ideally not happen if PreAuthorize works

        // Verify current password
        if (!encoder.matches(changePasswordRequest.getCurrentPassword(), currentUser.getPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Incorrect current password."));
        }

        // Check if new password is same as old
        if (encoder.matches(changePasswordRequest.getNewPassword(), currentUser.getPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: New password cannot be the same as the old password."));
        }

        // Encode and update password
        currentUser.setPassword(encoder.encode(changePasswordRequest.getNewPassword()));
        userRepository.save(currentUser);

        // Invalidate existing refresh tokens for security
        try {
            int deletedCount = refreshTokenService.deleteByUserId(userId);
            log.info("Invalidated {} refresh tokens for user ID {} after password change.", deletedCount, userId);
        } catch (Exception e) {
            // Log the error, but don't fail the whole operation just because token cleanup failed.
            // Consider if this should be a critical failure depending on security requirements.
            log.error("Could not invalidate refresh tokens for user ID {} after password change.", userId, e);
        }

        return ResponseEntity.ok(new MessageResponse("Password changed successfully."));
    }
}