package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

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
    void shouldThrowExceptionWhenTokenExpires() throws InterruptedException {
        String secret = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";

        JwtService jwtService = new JwtService(secret, 10);

        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );

        String token = jwtService.generateToken(user);

        Thread.sleep(20);

        assertThrows(
                ExpiredJwtException.class,
                () -> jwtService.extractEmail(token)
        );
    }
}
