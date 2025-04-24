package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.dto.JwtResponse;
import auth_with_h2.auth_experiment.dto.LoginRequest;
import auth_with_h2.auth_experiment.dto.SignupRequest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
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
class AuthIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate; // For making HTTP requests

    private static String accessToken; // Store token between tests

    private String createURL(String uri) {
        return "http://localhost:" + port + uri;
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
        assertThat(accessToken).isNotNull(); // Ensure token was obtained

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