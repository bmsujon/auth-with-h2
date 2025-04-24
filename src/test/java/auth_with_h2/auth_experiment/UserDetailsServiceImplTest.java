package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.entity.User;
import auth_with_h2.auth_experiment.repository.UserRepository;
import auth_with_h2.auth_experiment.service.UserDetailsServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks // Creates an instance of UserDetailsServiceImpl and injects mocks
    private UserDetailsServiceImpl userDetailsService;

    @Test
    void whenUserExists_loadUserByUsername_shouldReturnUserDetails() {
        // Arrange
        String username = "testuser";
        User mockUser = new User(username, "test@example.com", "password");
        mockUser.setId(1L); // Set ID if UserDetailsImpl uses it
        // Set roles if needed for UserDetailsImpl

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        // Act
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Assert
        assertNotNull(userDetails);
        assertEquals(username, userDetails.getUsername());
        assertEquals("password", userDetails.getPassword()); // Assuming UserDetailsImpl returns the raw password from User entity
        // Add assertions for authorities/roles if applicable
        verify(userRepository, times(1)).findByUsername(username);
    }

    @Test
    void whenUserDoesNotExist_loadUserByUsername_shouldThrowUsernameNotFoundException() {
        // Arrange
        String username = "nonexistent";
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(UsernameNotFoundException.class, () -> {
            userDetailsService.loadUserByUsername(username);
        }, "User Not Found with username: " + username); // Check exception message

        verify(userRepository, times(1)).findByUsername(username);
    }
}