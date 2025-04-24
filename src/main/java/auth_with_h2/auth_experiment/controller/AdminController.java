package auth_with_h2.auth_experiment.controller;

import auth_with_h2.auth_experiment.dto.MessageResponse;
import auth_with_h2.auth_experiment.dto.UserInfoResponse;
import auth_with_h2.auth_experiment.entity.User; // Ensure correct package
import auth_with_h2.auth_experiment.repository.UserRepository;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@Tag(name = "Admin API", description = "API endpoints for administrative tasks") // Separate tag for admin actions
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/admin") // Base path for admin endpoints
@PreAuthorize("hasRole('ADMIN')") // Apply authorization check at the class level for all methods
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @Operation(summary = "List all users", description = "Retrieves a list of all registered users. Requires ADMIN role.",
               security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully retrieved list of users",
                         content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                         array = @ArraySchema(schema = @Schema(implementation = UserInfoResponse.class)))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing JWT",
                         content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                         schema = @Schema(implementation = MessageResponse.class))),
            @ApiResponse(responseCode = "403", description = "Forbidden - User does not have ADMIN role",
                         content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                         schema = @Schema(implementation = MessageResponse.class))) // Spring Security's default AccessDeniedException handler or your global handler might manage this
    })
    @GetMapping("/users")
    public ResponseEntity<List<UserInfoResponse>> getAllUsers() {
        List<User> users = userRepository.findAll();

        // Map User entities to UserInfoResponse DTOs
        List<UserInfoResponse> userInfos = users.stream().map(user -> new UserInfoResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRoles().stream()
                    .map(role -> role.getName().name()) // Get role names as strings
                    .collect(Collectors.toList())
        )).collect(Collectors.toList());

        return ResponseEntity.ok(userInfos);
    }

    // --- Other admin endpoints (e.g., update roles, delete user) would go here ---

}