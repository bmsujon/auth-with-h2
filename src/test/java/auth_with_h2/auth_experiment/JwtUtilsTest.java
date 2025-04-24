package auth_with_h2.auth_experiment;

import auth_with_h2.auth_experiment.service.UserDetailsImpl;
import auth_with_h2.auth_experiment.utils.JwtUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils; // For setting @Value fields

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtUtilsTest {

    private JwtUtils jwtUtils;

    // Define the PLAIN secret first
    private final String plainSecret = "TestSecretKeyWhichIsDefinitelyLongEnoughForHS256Testing";
    // Store the BASE64 ENCODED version, as expected by JwtUtils
    private String base64EncodedSecret;
    
    private final int testExpirationMs = 60000; // 1 minute for testing

    private Key testKey; // Key derived from the DECODED secret

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        
        // Encode the plain secret to Base64
        base64EncodedSecret = Base64.getEncoder().encodeToString(plainSecret.getBytes(StandardCharsets.UTF_8));
        
        // Use ReflectionTestUtils to set the @Value fields with the BASE64 ENCODED secret
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", base64EncodedSecret);
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", testExpirationMs);
        
        // Create the testKey by DECODING the Base64 secret, mirroring JwtUtils.key()
        testKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64EncodedSecret));
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
    void validateJwtToken_withExpiredToken_shouldReturnFalse() {
        // Create a token that expired in the past
        String expiredToken = Jwts.builder()
                .setSubject("expireduser")
                .setIssuedAt(new Date(System.currentTimeMillis() - 2 * testExpirationMs))
                .setExpiration(new Date(System.currentTimeMillis() - testExpirationMs)) // Expired
                .signWith(testKey, SignatureAlgorithm.HS256)
                .compact();

        // Expect false because validateJwtToken now catches the exception and returns false
        assertFalse(jwtUtils.validateJwtToken(expiredToken));
    }

     @Test
     void validateJwtToken_withInvalidSignature_shouldReturnFalse() {
         // Use a different secret and derive its key
         String differentPlainSecret = "AnotherSecretKeyThatIsDefinitelyLongEnoughForTestingPurposesToo";
         String differentBase64Secret = Base64.getEncoder().encodeToString(differentPlainSecret.getBytes(StandardCharsets.UTF_8));
         Key differentKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(differentBase64Secret));

         // Create token signed with the DIFFERENT key
         String tokenWithWrongSignature = Jwts.builder()
                 .setSubject("badsignature")
                 .setIssuedAt(new Date())
                 .setExpiration(new Date(System.currentTimeMillis() + testExpirationMs))
                 .signWith(differentKey, SignatureAlgorithm.HS256)
                 .compact();

         // Expect false as jwtUtils validates with its own internal key and catches SignatureException
         assertFalse(jwtUtils.validateJwtToken(tokenWithWrongSignature));
     }

     @Test
     void validateJwtToken_withMalformedToken_shouldReturnFalse() {
         String malformedToken = "this.is.not.a.jwt";
         
         // Expect false as validateJwtToken catches MalformedJwtException
         assertFalse(jwtUtils.validateJwtToken(malformedToken));
     }

     @Test
     void validateJwtToken_withEmptyOrNullToken_shouldReturnFalse() {
         // Expect false as validateJwtToken catches IllegalArgumentException
         assertFalse(jwtUtils.validateJwtToken(null));
         assertFalse(jwtUtils.validateJwtToken(""));
         assertFalse(jwtUtils.validateJwtToken(" "));
     }
}
