
package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.configs.AuthEntryPointJwt;
// WebSecurityConfig is now loaded automatically by @SpringBootTest, no need to @Import
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc; // Import AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest; // Import SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;


import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

// --- Use @SpringBootTest and @AutoConfigureMockMvc ---
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper; // For converting objects to JSON

    // Mock dependencies needed for the tests.
    // AuthenticationManager might be trickier to mock in full context, but let's try.
    @MockBean
    private AuthenticationManager authenticationManager;

    // PasswordEncoder is often provided by the context, but mocking might be okay if UserRepository is mocked.
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

    @MockBean
    private PasswordResetService passwordResetService;

    // UserDetailsServiceImpl is a service, mocking is appropriate if not testing its logic directly.
    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    // Let the actual AuthEntryPointJwt bean handle unauthorized access
    


    @BeforeEach
    void setUpMocks() {
        // Configure mocks as needed for each test or globally if applicable
        Role mockRole = new Role();
        mockRole.setId(1);
        mockRole.setName(ERole.ROLE_OTHERS);
        when(roleRepository.findByName(ERole.ROLE_OTHERS)).thenReturn(Optional.of(mockRole));
        when(passwordEncoder.encode(any(String.class))).thenReturn("hashedPassword");

        // Example: Mock user loading for @WithUserDetails or manual context setup
        UserDetailsImpl mockUserDetails = new UserDetailsImpl(
                1L, "testuser", "test@example.com", "encodedPassword",
                List.of(new SimpleGrantedAuthority("ROLE_OTHERS"))
        );
        when(userDetailsService.loadUserByUsername("testuser")).thenReturn(mockUserDetails);

    }
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }


    @Test
    void whenSigninWithValidCredentials_shouldReturnJwtResponse() throws Exception {
        // Arrange
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("testuser");
        loginRequest.setPassword("password");

        UserDetailsImpl signinMockUserDetails = new UserDetailsImpl(
                1L, "testuser", "test@example.com", "encodedPassword",
                List.of(new SimpleGrantedAuthority("ROLE_OTHERS"))
        );
        Authentication mockAuth = new UsernamePasswordAuthenticationToken(signinMockUserDetails, null, signinMockUserDetails.getAuthorities());

        // Mock AuthenticationManager behavior
        when(authenticationManager.authenticate(
                argThat(token -> token instanceof UsernamePasswordAuthenticationToken &&
                        token.getName().equals("testuser") &&
                        token.getCredentials().equals("password"))
        )).thenReturn(mockAuth);

        // Mock other necessary services
        when(jwtUtils.generateJwtToken(mockAuth)).thenReturn("mockAccessToken");
        // Assume RefreshTokenService.createRefreshToken returns a valid object
        when(refreshTokenService.createRefreshToken(anyLong())).thenReturn(new auth_with_h2.auth_experiment.entity.RefreshToken()); // Adjust as needed

        // Act & Assert
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

        // Mock dependencies
        Role mockRole = new Role();
        mockRole.setName(ERole.ROLE_OTHERS);
        when(roleRepository.findByName(ERole.ROLE_OTHERS)).thenReturn(Optional.of(mockRole));
        when(userRepository.existsByUsername(signupRequest.getUsername())).thenReturn(false);
        when(userRepository.existsByEmail(signupRequest.getEmail())).thenReturn(false);
        when(userRepository.save(any(auth_with_h2.auth_experiment.entity.User.class))).thenAnswer(i -> i.getArguments()[0]); // Mock save

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully!"));
    }

    @Test
    void whenSignupWithExistingUsername_shouldReturnBadRequest() throws Exception {
        // Arrange
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername("existinguser");
        signupRequest.setEmail("newemail@example.com");
        signupRequest.setPassword("password123");

        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        // Act & Assert
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest))
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Username is already taken!"));
    }

    @Test
        // No @With... annotation needed if we manually set context or test unauthenticated
    void whenGetMeAuthenticated_shouldReturnUserInfo() throws Exception {
        // Arrange: Manually set up Security Context for an authenticated user
        UserDetailsImpl mockUserDetails = new UserDetailsImpl(
                1L, "testuser", "test@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_OTHERS"))
        );
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                mockUserDetails, null, mockUserDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Act & Assert
        mockMvc.perform(get("/api/auth/me")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.id").value(1L));
    }

    @Test
    void whenGetMeUnauthenticated_shouldReturnUnauthorized() throws Exception {
        // Arrange: Ensure security context is clear (redundant with @AfterEach but safe)
        SecurityContextHolder.clearContext();

        // Act & Assert
        mockMvc.perform(get("/api/auth/me")
                        .contentType(MediaType.APPLICATION_JSON))
                // Expect 401 because WebSecurityConfig now enforces .authenticated()
                // at the filter level, and the ACTUAL AuthEntryPointJwt should be triggered.
                .andExpect(status().isUnauthorized());
    }
    // Add more tests...
}

