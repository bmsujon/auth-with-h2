package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.entity.Role;
import auth_with_h2.auth_experiment.entity.User;
import auth_with_h2.auth_experiment.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat; // Using AssertJ

@DataJpaTest // Configures H2, Hibernate, Spring Data JPA
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager; // Helper for persisting entities in tests

    @Autowired
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        // Arrange: Create and persist a test user before each test
        testUser = new User("testuser", "test@example.com", "password");
        entityManager.persist(testUser); // Use entityManager to save
        entityManager.flush(); // Ensure data is written to DB
    }

     @AfterEach
     void tearDown() {
         // Clean up database if necessary (entityManager usually handles rollback)
         // entityManager.clear();
     }


    @Test
    void findByUsername_whenUserExists_shouldReturnUser() {
        // Act
        Optional<User> foundUser = userRepository.findByUsername("testuser");

        // Assert
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getUsername()).isEqualTo(testUser.getUsername());
        assertThat(foundUser.get().getEmail()).isEqualTo(testUser.getEmail());
    }

    @Test
    void findByUsername_whenUserDoesNotExist_shouldReturnEmpty() {
        // Act
        Optional<User> foundUser = userRepository.findByUsername("nonexistent");

        // Assert
        assertThat(foundUser).isNotPresent();
    }

    @Test
    void existsByUsername_whenUserExists_shouldReturnTrue() {
        // Act
        boolean exists = userRepository.existsByUsername("testuser");

        // Assert
        assertThat(exists).isTrue();
    }

    @Test
    void existsByUsername_whenUserDoesNotExist_shouldReturnFalse() {
        // Act
        boolean exists = userRepository.existsByUsername("nonexistent");

        // Assert
        assertThat(exists).isFalse();
    }

    @Test
    void existsByEmail_whenEmailExists_shouldReturnTrue() {
         // Act
         boolean exists = userRepository.existsByEmail("test@example.com");

         // Assert
         assertThat(exists).isTrue();
    }

     @Test
     void existsByEmail_whenEmailDoesNotExist_shouldReturnFalse() {
         // Act
         boolean exists = userRepository.existsByEmail("nonexistent@example.com");

         // Assert
         assertThat(exists).isFalse();
     }

    // Add tests for RoleRepository and RefreshTokenRepository similarly
}