package auth_with_h2.auth_experiment.dataLoaders;

import auth_with_h2.auth_experiment.enums.ERole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import auth_with_h2.auth_experiment.entity.Role;
import auth_with_h2.auth_experiment.repository.RoleRepository;

import java.util.Arrays;
import java.util.Optional;

@Component
public class DataLoader implements ApplicationRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Arrays.stream(ERole.values()).forEach(roleName -> {
            Optional<Role> role = roleRepository.findByName(roleName);
            if (role.isEmpty()) {
                // Use the no-args constructor and set the name via setter
                Role newRole = new Role();
                newRole.setName(roleName);
                roleRepository.save(newRole); // JPA will generate the ID on save
                System.out.println("Inserted role: " + roleName);
            }
        });
    }
}
