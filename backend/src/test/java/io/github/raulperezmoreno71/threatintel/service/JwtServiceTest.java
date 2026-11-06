package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
    private static final String SECRET = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";

    @Test
    void shouldParseGeneratedTokenIntoEmailAndCurrentVersion() {
        JwtService service = new JwtService(SECRET, 3600000);
        User user = new User("user@example.com", "hash", UserStatus.ACTIVE);
        user.incrementSessionVersion();
        user.incrementSessionVersion();

        var identity = service.parseToken(service.generateToken(user));

        assertEquals("user@example.com", identity.email());
        assertEquals(2L, identity.sessionVersion());
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, 3L, Long.MAX_VALUE})
    void shouldAcceptNonnegativeIntegerVersionsWithoutTruncation(long version) {
        JwtService service = new JwtService(SECRET, 3600000);
        var identity = service.parseToken(signedToken("user@example.com", version,
                new Date(System.currentTimeMillis() + 3600000)));
        assertEquals(version, identity.sessionVersion());
    }

    static Stream<Object> invalidSessionVersions() {
        return Stream.of(null, -1L, 0.5, 0.0, "0", true, List.of(0),
                new BigInteger("9223372036854775808"));
    }

    @ParameterizedTest
    @MethodSource("invalidSessionVersions")
    void shouldRejectMissingOrInvalidSessionVersions(Object version) {
        JwtService service = new JwtService(SECRET, 3600000);
        String token = signedToken("user@example.com", version,
                new Date(System.currentTimeMillis() + 3600000));
        assertThrows(JwtException.class, () -> service.parseToken(token));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    void shouldRejectTokensWithoutANonblankEmail(String email) {
        JwtService service = new JwtService(SECRET, 3600000);
        String token = signedToken(email, 0, new Date(System.currentTimeMillis() + 3600000));
        assertThrows(JwtException.class, () -> service.parseToken(token));
    }

    @Test
    void shouldRejectTokensWithoutExpiration() {
        JwtService service = new JwtService(SECRET, 3600000);
        assertThrows(JwtException.class, () -> service.parseToken(signedToken("user@example.com", 0, null)));
    }

    @Test
    void shouldRejectExpiredTokensWhenReadingIdentity() {
        JwtService service = new JwtService(SECRET, 3600000);
        String token = signedToken("user@example.com", 0, new Date(System.currentTimeMillis() - 60000));
        assertThrows(ExpiredJwtException.class, () -> service.parseToken(token));
    }

    @Test
    void shouldRejectWrongSignatureWhenReadingIdentity() {
        JwtService service = new JwtService("y/EAFsHOGmJdElwFjzi/2CsPUilZGiDOhcftfcNh2gY=", 3600000);
        String token = signedToken("user@example.com", 0, new Date(System.currentTimeMillis() + 3600000));
        assertThrows(SignatureException.class, () -> service.parseToken(token));
    }

    private String signedToken(String email, Object version, Date expiration) {
        return Jwts.builder().subject(email).claim("sessionVersion", version).expiration(expiration)
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();
    }

    @Test
    void shouldIncludeCurrentSessionVersionInSignedToken() {
        String secret = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";
        JwtService service = new JwtService(secret, 3600000);
        User user = new User("user@example.com", "hash", UserStatus.ACTIVE);
        user.incrementSessionVersion();
        user.incrementSessionVersion();

        String token = service.generateToken(user);
        var claims = Jwts.parser().verifyWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret)))
                .build().parseSignedClaims(token).getPayload();

        assertEquals(2L, claims.get("sessionVersion", Long.class));
    }

    @Test
    void shouldGenerateTokenAndExtractEmail() {
        String secret = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";
        JwtService jwtService = new JwtService(secret, 3600000);

        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        String token = jwtService.generateToken(user);

        assertNotNull(token);
        assertEquals("user@example.com", jwtService.extractEmail(token));
    }

    @Test
    void shouldRejectTokenSignedWithDifferentKey() {
        String secretA = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";
        String secretB = "y/EAFsHOGmJdElwFjzi/2CsPUilZGiDOhcftfcNh2gY=";

        JwtService jwtServiceA = new JwtService(secretA, 3600000);
        JwtService jwtServiceB = new JwtService(secretB, 3600000);

        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        String token = jwtServiceA.generateToken(user);

        assertThrows(
                SignatureException.class,
                () -> jwtServiceB.extractEmail(token)
        );
    }

    @Test
    void shouldThrowExceptionWhenTokenExpires() {
        String secret = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";

        JwtService jwtService = new JwtService(secret, -1);

        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        String token = jwtService.generateToken(user);

        assertThrows(
                ExpiredJwtException.class,
                () -> jwtService.extractEmail(token)
        );
    }
}
