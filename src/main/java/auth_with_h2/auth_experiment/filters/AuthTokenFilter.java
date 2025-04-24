package auth_with_h2.auth_experiment.filters;

import java.io.IOException;

import auth_with_h2.auth_experiment.service.UserDetailsServiceImpl;
import auth_with_h2.auth_experiment.utils.JwtUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String jwt = null;
        try {
            jwt = parseJwt(request);
            if (jwt != null) {
                // Attempt to get username; this implicitly validates the token
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // If successful (no exception thrown), load user details and set authentication
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null, // Credentials not needed as JWT is verified
                                userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token is expired: {} for token: {}", e.getMessage(), jwt);
            // Optionally: Set a request attribute or header to indicate expiry
            // request.setAttribute("jwtExpired", true);
            // response.setHeader("X-Token-Status", "Expired");
        } catch (MalformedJwtException | UnsupportedJwtException | SignatureException | IllegalArgumentException e) {
            // Catch specific JWT validation errors (other than expiry)
            logger.error("Invalid JWT token: {} for token: {}", e.getMessage(), jwt);
            // request.setAttribute("jwtInvalid", true);
            // response.setHeader("X-Token-Status", "Invalid");
        } catch (Exception e) {
            // Catch any other unexpected errors during authentication context setup
            logger.error("Cannot set user authentication: {}", e.getMessage(), e);
        }

        // Continue the filter chain regardless of whether authentication was set
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }
}
