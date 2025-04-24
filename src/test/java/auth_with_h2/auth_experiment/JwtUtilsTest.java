package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.service.UserDetailsImpl;
import auth_with_h2.auth_experiment.utils.JwtUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils; // For setting @Value fields

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtUtilsTest {

    private JwtUtils jwtUtils;

    // Use a fixed, known secret for testing consistency
    private final String testSecret = "TestSecretKeyWhichIsDefinitelyLongEnoughForHS256Testing";
    private final int testExpirationMs = 60000; // 1 minute for testing

    private Key testKey;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        // Use ReflectionTestUtils to set the @Value fields for the test instance
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", testSecret);
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", testExpirationMs);
        testKey = Keys.hmacShaKeyFor(testSecret.getBytes(StandardCharsets.UTF_8));
    }

    private Authentication createMockAuthentication(String username) {
        Authentication authentication = mock(Authentication.class);
        UserDetailsImpl userDetails = mock(UserDetailsImpl.class);
        when(userDetails.getUsername()).thenReturn(username);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        return authentication;
    }

    @Test
    void generateJwtToken_shouldCreateValidToken() {
        Authentication authentication = createMockAuthentication("testuser");
        String token = jwtUtils.generateJwtToken(authentication);

        assertNotNull(token);
        // Validate the token using the same key
        String usernameFromToken = Jwts.parserBuilder()
                                       .setSigningKey(testKey)
                                       .build()
                                       .parseClaimsJws(token)
                                       .getBody()
                                       .getSubject();
        assertEquals("testuser", usernameFromToken);
    }

    @Test
    void getUserNameFromJwtToken_shouldReturnUsername() {
        Authentication authentication = createMockAuthentication("anotheruser");
        String token = jwtUtils.generateJwtToken(authentication);

        String username = jwtUtils.getUserNameFromJwtToken(token);
        assertEquals("anotheruser", username);
    }

    @Test
    void validateJwtToken_withValidToken_shouldReturnTrue() {
        Authentication authentication = createMockAuthentication("validuser");
        String token = jwtUtils.generateJwtToken(authentication);

        assertTrue(jwtUtils.validateJwtToken(token));
    }

    @Test
    void validateJwtToken_withExpiredToken_shouldReturnFalseAndLog() {
        // Create a token that expired in the past
        String expiredToken = Jwts.builder()
                .setSubject("expireduser")
                .setIssuedAt(new Date(System.currentTimeMillis() - 2 * testExpirationMs))
                .setExpiration(new Date(System.currentTimeMillis() - testExpirationMs)) // Expired
                .signWith(testKey, SignatureAlgorithm.HS256)
                .compact();

        // Expect false, and ideally check logs (can use Logback test appenders)
        assertFalse(jwtUtils.validateJwtToken(expiredToken));
        // Add logging assertion if needed
    }

     @Test
     void validateJwtToken_withInvalidSignature_shouldReturnFalseAndLog() {
         // Use a key that meets length requirements but is different from testSecret
         String differentSecret = "AnotherSecretKeyThatIsDefinitelyLongEnoughForTestingPurposesToo"; // >= 32 chars
         assertThat(differentSecret.getBytes(StandardCharsets.UTF_8).length * 8).isGreaterThanOrEqualTo(256); // Verify length

         String tokenWithWrongSignature = Jwts.builder()
                 .setSubject("badsignature")
                 .setIssuedAt(new Date())
                 .setExpiration(new Date(System.currentTimeMillis() + testExpirationMs))
                 .signWith(Keys.hmacShaKeyFor(differentSecret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256) // Use the longer, different key
                 .compact();

         assertFalse(jwtUtils.validateJwtToken(tokenWithWrongSignature));
         // Add logging assertion if needed
     }

     @Test
     void validateJwtToken_withMalformedToken_shouldReturnFalseAndLog() {
         String malformedToken = "this.is.not.a.jwt";
         assertFalse(jwtUtils.validateJwtToken(malformedToken));
         // Add logging assertion if needed
     }

     @Test
     void validateJwtToken_withEmptyOrNullToken_shouldReturnFalseAndLog() {
         assertFalse(jwtUtils.validateJwtToken(null));
         assertFalse(jwtUtils.validateJwtToken(""));
         assertFalse(jwtUtils.validateJwtToken(" "));
         // Add logging assertion if needed
     }
}