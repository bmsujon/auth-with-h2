package auth_with_h2.auth_experiment.repository;

import java.util.Optional;

import auth_with_h2.auth_experiment.entity.Role;
import auth_with_h2.auth_experiment.enums.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}