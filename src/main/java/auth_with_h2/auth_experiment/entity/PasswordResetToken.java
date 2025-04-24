package auth_with_h2.auth_experiment.entity; // Adjusted package to match User/Role

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "password_reset_tokens")
@Data
@NoArgsConstructor
public class PasswordResetToken {

    private static final int EXPIRATION_MINUTES = 60; // e.g., 1 hour validity

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    @Column(nullable = false)
    private Instant expiryDate;

    public PasswordResetToken(String token, User user) {
        this.token = token;
        this.user = user;
        this.expiryDate = calculateExpiryDate(EXPIRATION_MINUTES);
    }

    private Instant calculateExpiryDate(int expiryTimeInMinutes) {
        return Instant.now().plusSeconds(expiryTimeInMinutes * 60);
    }

    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }
}