package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.dto.JwtResponse;
import auth_with_h2.auth_experiment.dto.LoginRequest;
import auth_with_h2.auth_experiment.dto.SignupRequest;
import auth_with_h2.auth_experiment.repository.UserRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort; // Get random port
import org.springframework.http.*;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT) // Load full context, use random port
@TestMethodOrder(MethodOrderer.OrderAnnotation.class) // Control test execution order if needed
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // Allow state sharing between tests
class AuthIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate; // For making HTTP requests

    @Autowired
    private UserRepository userRepository; // Inject repository for cleanup

    // accessToken field relies on PER_CLASS lifecycle and NO context reset between ordered tests
    private static String accessToken; // Store token between tests

    private String createURL(String uri) {
        return "http://localhost:" + port + uri;
    }

    // Clean up the specific test user after all test methods
    // This preserves the user state between ordered tests
    @AfterAll
    void cleanupUserAfterAllTests() {
        System.out.println("Running @AfterAll cleanup for integration_user...");
        userRepository.findByUsername("integration_user").ifPresent(user -> {
            userRepository.delete(user);
            System.out.println("Deleted integration_user.");
        });
        accessToken = null; // Clear static token
    }

    @Test
    @Order(1) // Run signup first
    void signup_shouldRegisterUserSuccessfully() {
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername("integration_user");
        signupRequest.setEmail("integration@example.com");
        signupRequest.setPassword("password123");
        signupRequest.setRole(Set.of("others")); // Use role name from ERole

        ResponseEntity<String> response = restTemplate.postForEntity(
                createURL("/api/auth/signup"),
                signupRequest,
                String.class // Expecting a simple message response
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("User registered successfully!");
    }

    @Test
    @Order(2) // Run signin after signup
    void signin_withValidCredentials_shouldReturnTokensAndUserDetails() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("integration_user");
        loginRequest.setPassword("password123");

        ResponseEntity<JwtResponse> response = restTemplate.postForEntity(
                createURL("/api/auth/signin"),
                loginRequest,
                JwtResponse.class // Expecting the JwtResponse DTO
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getToken()).isNotBlank();
        assertThat(response.getBody().getRefreshToken()).isNotBlank();
        assertThat(response.getBody().getUsername()).isEqualTo("integration_user");
        assertThat(response.getBody().getEmail()).isEqualTo("integration@example.com");
        assertThat(response.getBody().getRoles()).contains("ROLE_OTHERS"); // Check role prefix

        // Store the token for the next test
        accessToken = response.getBody().getToken();
    }

    @Test
    @Order(3) // Run secured endpoint access after signin
    void getMe_withValidToken_shouldReturnUserInfo() {
        assertThat(accessToken).withFailMessage("Access token was null. Check if signin test ran successfully and set the token.").isNotNull();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken); // Set Authorization header
        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(
                createURL("/api/auth/me"),
                HttpMethod.GET,
                entity,
                String.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"username\":\"integration_user\"");
        assertThat(response.getBody()).contains("\"email\":\"integration@example.com\"");
    }

     @Test
     @Order(4)
     void getMe_withoutToken_shouldReturnUnauthorized() {
         HttpHeaders headers = new HttpHeaders();
         HttpEntity<String> entity = new HttpEntity<>(headers); // No token

         ResponseEntity<String> response = restTemplate.exchange(
                 createURL("/api/auth/me"),
                 HttpMethod.GET,
                 entity,
                 String.class
         );

         assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
     }

    // Add more integration tests for refresh token flow, password change, signout etc.
}
