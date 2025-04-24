package auth_with_h2.auth_experiment.utils;

import java.security.Key;
import java.util.Date;

import auth_with_h2.auth_experiment.service.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Parses the JWT token to extract claims. This method implicitly validates the token
     * (signature, expiration, format) according to the JJWT library.
     *
     * @param token The JWT token string.
     * @return The Claims object containing the token's payload.
     * @throws ExpiredJwtException      if the token is expired.
     * @throws UnsupportedJwtException  if the token format is not supported.
     * @throws MalformedJwtException    if the token is structurally invalid.
     * @throws SignatureException       if the token signature is invalid.
     * @throws IllegalArgumentException if the token string is null, empty or only whitespace.
     */
    private Claims parseClaimsJws(String token) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        // IllegalArgumentException will be thrown by the parser if token is null/empty/whitespace
        // although AuthTokenFilter checks for null/empty beforehand.
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody();
    }

    public String getUserNameFromJwtToken(String token) {
        // This now implicitly validates the token before extracting the subject
        return parseClaimsJws(token).getSubject();
    }

    /**
     * Validates the JWT token's signature, expiration, and format.
     * Catches common JWT exceptions, logs them, and returns a boolean result.
     *
     * @param authToken The JWT token string.
     * @return true if the token is valid, false otherwise.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            // Parsing the claims validates the token.
            parseClaimsJws(authToken);
            return true; // Return true only if no exception was thrown
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            // This catches null/empty/whitespace tokens passed to the parser
            logger.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) { // Catch any other potential unexpected exceptions during parsing
            logger.error("JWT validation failed with unexpected error: {}", e.getMessage(), e);
        }

        return false; // Return false if any exception occurred
    }
}
