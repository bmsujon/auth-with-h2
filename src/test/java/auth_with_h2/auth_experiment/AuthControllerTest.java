package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.configs.AuthEntryPointJwt;
import auth_with_h2.auth_experiment.configs.WebSecurityConfig; // Import security config
import auth_with_h2.auth_experiment.controller.AuthController;
import auth_with_h2.auth_experiment.dto.LoginRequest;
import auth_with_h2.auth_experiment.dto.SignupRequest;
import auth_with_h2.auth_experiment.entity.Role;
import auth_with_h2.auth_experiment.enums.ERole;
import auth_with_h2.auth_experiment.repository.RoleRepository;
import auth_with_h2.auth_experiment.repository.UserRepository;
import auth_with_h2.auth_experiment.service.PasswordResetService;
import auth_with_h2.auth_experiment.service.RefreshTokenService;
import auth_with_h2.auth_experiment.service.UserDetailsImpl;
import auth_with_h2.auth_experiment.service.UserDetailsServiceImpl;
import auth_with_h2.auth_experiment.utils.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import; // Import necessary config
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser; // For secured endpoints
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.util.List;
import java.util.Optional;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;


// Target the specific controller
@WebMvcTest(AuthController.class)
// Import necessary security configuration for the test context
@Import(WebSecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper; // For converting objects to JSON

    // Mock all dependencies used by AuthController
    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private RefreshTokenService refreshTokenService;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RoleRepository roleRepository;

    // --- Add MockBean for the missing service ---
    @MockBean
    private PasswordResetService passwordResetService;

    // Mock UserDetailsService because WebSecurityConfig depends on it
    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    @MockBean // <<< Add this MockBean
    private AuthEntryPointJwt unauthorizedHandler;


    @BeforeEach
    void setUpMocks() {
        // Configure AuthEntryPointJwt mock using an explicit Answer implementation
        Answer<Void> commenceAnswer = new Answer<Void>() {
            @Override
            // Remove 'throws Throwable' from the signature here
            public Void answer(InvocationOnMock invocation) {
                // HttpServletRequest request = invocation.getArgument(0); // If needed
                HttpServletResponse response = invocation.getArgument(1);
                AuthenticationException authException = invocation.getArgument(2);

                try {
                    // The code that might throw IOException
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " + authException.getMessage());

                    // If the actual commence logic could throw ServletException,
                    // you might need to simulate that or handle it here too.
                    // For now, we focus on IOException from sendError.

                } catch (IOException e) {
                    // Handle unexpected IO exception during test mock execution
                    // Rethrow as an unchecked exception to fail the test clearly
                    throw new RuntimeException("Unexpected IOException in mock commence", e);
                }
                // If you needed to handle ServletException:
                // catch (ServletException e) {
                //     throw new RuntimeException("Unexpected ServletException in mock commence", e);
                // }

                return null; // Void method returns null
            }
        };

        // Apply the answer to the mock
        // The structure doAnswer(...).when(mock).method(...) is correct here.
        try {
            doAnswer(commenceAnswer)
                    .when(unauthorizedHandler)
                    .commence(
                            any(HttpServletRequest.class),
                            any(HttpServletResponse.class),
                            any(AuthenticationException.class)
                    );
        } catch (IOException | ServletException e) {
            // This catch block is technically needed for the compiler if the .commence(...)
            // signature itself forces handling, even though doAnswer should manage it.
            // We rethrow as RuntimeException because these shouldn't happen during mock setup.
            throw new RuntimeException("Exception during mock setup for commence", e);
        }


        // If you had other @BeforeEach setup, keep it here
    }
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }


    @Test
    void whenSigninWithValidCredentials_shouldReturnJwtResponse() throws Exception {
        // ... (signin test code remains the same) ...
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password");

        UserDetailsImpl signinMockUserDetails = new UserDetailsImpl(
                1L, "testuser", "test@example.com", "encodedPassword",
                List.of(new SimpleGrantedAuthority("ROLE_OTHERS"))
        );
        Authentication mockAuth = mock(Authentication.class);
        when(mockAuth.getPrincipal()).thenReturn(signinMockUserDetails);
        when(authenticationManager.authenticate(any())).thenReturn(mockAuth);
        when(jwtUtils.generateJwtToken(mockAuth)).thenReturn("mockAccessToken");

        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("mockAccessToken"))
                .andExpect(jsonPath("$.id").value(signinMockUserDetails.getId()))
                .andExpect(jsonPath("$.username").value(signinMockUserDetails.getUsername()))
                .andExpect(jsonPath("$.email").value(signinMockUserDetails.getEmail()))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_OTHERS"));
    }

    @Test
    void whenSignupWithValidData_shouldReturnSuccessMessage() throws Exception {
        // Arrange: Setup the request object
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername("newuser");
        signupRequest.setEmail("newuser@example.com");
        signupRequest.setPassword("password123");
        // Assuming the controller defaults to ROLE_OTHERS if role set is null/empty
        // or you can explicitly set it: signupRequest.setRole(Set.of("others"));

        // Mock dependencies
        when(passwordEncoder.encode(any(String.class))).thenReturn("hashedPassword");

        // --- FIX START ---
        // Create the mock Role object using the available constructor
        Role mockRole = new Role(); // Use no-args constructor
        mockRole.setId(1); // Optional: Set a dummy ID if needed elsewhere
        mockRole.setName(ERole.ROLE_OTHERS); // Set the name

        // Mock RoleRepository to return the created mock Role
        when(roleRepository.findByName(ERole.ROLE_OTHERS)).thenReturn(Optional.of(mockRole));
        // --- FIX END ---

        // Mock other repository methods if the controller uses them directly during signup
        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        // when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]); // Mock save if needed

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON) // Add content type
                        .content(objectMapper.writeValueAsString(signupRequest)) // Add request body
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully!"));
    }
     @Test
     void whenSignupWithExistingUsername_shouldReturnBadRequest() throws Exception {
         // Arrange: Setup the request object
         SignupRequest signupRequest = new SignupRequest();
         signupRequest.setUsername("existinguser");
         signupRequest.setEmail("newemail@example.com");
         signupRequest.setPassword("password123");
         // signupRequest.setRole(Set.of("others"));

         // Mock the exists check
         when(userRepository.existsByUsername("existinguser")).thenReturn(true); // Mock the condition

         // Act & Assert
         mockMvc.perform(post("/api/auth/signup")
                         .contentType(MediaType.APPLICATION_JSON) // Add content type
                         .content(objectMapper.writeValueAsString(signupRequest)) // Add request body
                 )
                 .andExpect(status().isBadRequest())
                 .andExpect(jsonPath("$.message").value("Error: Username is already taken!"));
     }

    @Test
    // --- FIX: Replace @WithMockUser with @WithUserDetails ---
    // value = "testuser" -> The username to load
    // userDetailsServiceBeanName = "userDetailsServiceImpl" -> The bean name of your UserDetailsService mock
    void whenGetMeAuthenticated_shouldReturnUserInfo() throws Exception {

        // --- Manually set up Security Context ---
        UserDetailsImpl mockUserDetails = new UserDetailsImpl(
                1L,
                "testuser",
                "test@example.com",
                "password", // Password doesn't matter here
                List.of(new SimpleGrantedAuthority("ROLE_OTHERS"))
        );
        // Create an Authentication object suitable for testing
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        mockUserDetails, // Principal
                        null,            // Credentials (not needed for this test)
                        mockUserDetails.getAuthorities() // Authorities
                );
        // Set the security context for this test execution
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // --- End of manual setup ---


        // Act & Assert
        mockMvc.perform(get("/api/auth/me")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                // Assertions should match the details provided in mockUserDetails
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.id").value(1L));
    }
    @Test
    void whenGetMeUnauthenticated_shouldReturnUnauthorized() throws Exception {
        // No changes needed inside the test method itself
        mockMvc.perform(get("/api/auth/me")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized()); // Still expect 401
    }
    // Add more tests for other endpoints: /validate, /refreshtoken, /signout, /change-password
    // Remember to use @WithMockUser for secured endpoints.
    // Test validation failures (e.g., empty username/password).
    // Test role-based access if applicable (e.g., @WithMockUser(roles={"ADMIN"})).
}