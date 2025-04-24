package auth_with_h2.auth_experiment.configs;

import auth_with_h2.auth_experiment.filters.AuthTokenFilter;
import auth_with_h2.auth_experiment.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order; // <<<--- Add this import
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer; // <<<--- Add this import
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    // Keep PUBLIC_WHITELIST as is, including /h2-console/**
    private static final String[] PUBLIC_WHITELIST = {
            "/api/auth/**",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/swagger-resources/**",
            "/webjars/**",
            "/h2-console/**", // Keep H2 console public
            "/favicon.ico"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // ... other configs like csrf, cors, sessionManagement ...
                .exceptionHandling(exception -> exception
                                .authenticationEntryPoint(unauthorizedHandler) // Your AuthEntryPointJwt bean
                        // .accessDeniedHandler(...) // Optional: Define how 403 is handled
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/signin", "/api/auth/signup", "/api/auth/refreshtoken", "/api/auth/forgot-password", "/api/auth/reset-password").permitAll() // Public endpoints
                        // **** Crucial Line ****
                        .requestMatchers("/api/auth/me", "/api/auth/validate", "/api/auth/signout", "/api/auth/change-password").authenticated() // Requires authentication
                        // **** ---- ****
                        .anyRequest().authenticated() // Default deny or specific rules
                );

        // http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Removed the old 'securityFilterChain' bean as it was causing confusion
    // with the two ordered beans below.

    // Security Filter Chain specifically for H2 Console
    @Bean
    @Order(1) // Process H2 console requests first
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(AntPathRequestMatcher.antMatcher("/h2-console/**")) // Apply this chain ONLY to H2 console paths
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll(); // Explicitly permit H2 console
                })
                .csrf(csrf -> csrf.disable()) // Disable CSRF for H2 console
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)); // Allow framing for H2 console
        return http.build();
    }

    // Default Security Filter Chain for everything else
    // Default Security Filter Chain for everything else
    @Bean
    @Order(2) // Process other requests after H2 console
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler)) // This handles failed authentication attempts
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Permit public paths
                        .requestMatchers(
                                "/api/auth/signin",
                                "/api/auth/signup",
                                "/api/auth/refreshtoken",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password",
                                // Swagger UI paths
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**",
                                "/favicon.ico"
                        ).permitAll()
                        // --- Explicitly require authentication for /me ---
                        .requestMatchers("/api/auth/me").authenticated()
                        // --- Secure admin endpoints ---
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        // --- Secure other potentially sensitive auth endpoints ---
                        // validate, change-password, signout are already covered by @PreAuthorize,
                        // but adding them here provides defense in depth and ensures 401 if filter fails.
                        .requestMatchers("/api/auth/validate", "/api/auth/change-password", "/api/auth/signout").authenticated()
                        // Secure all other requests by default
                        .anyRequest().authenticated()
                );

        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
