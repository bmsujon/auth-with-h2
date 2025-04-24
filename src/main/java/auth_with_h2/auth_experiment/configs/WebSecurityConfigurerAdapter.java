package auth_with_h2.auth_experiment.configs;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public abstract class WebSecurityConfigurerAdapter {

    public abstract void configure(HttpSecurity http);
}
