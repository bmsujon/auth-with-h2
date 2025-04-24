package auth_with_h2.auth_experiment.repository;

import auth_with_h2.auth_experiment.entity.PasswordResetToken;
import auth_with_h2.auth_experiment.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByToken(String token);

    Optional<PasswordResetToken> findByUser(User user);

    @Modifying // Necessary for delete queries
    void deleteByExpiryDateLessThan(Instant now);

    @Modifying
    void deleteByUser(User user);
}