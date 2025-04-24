package auth_with_h2.auth_experiment.repository;

import java.util.Optional;

import auth_with_h2.auth_experiment.entity.RefreshToken;
import auth_with_h2.auth_experiment.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;


@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    
    @Modifying
    int deleteByUser(User user);
}