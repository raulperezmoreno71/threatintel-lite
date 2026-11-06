package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtService(@Value("${jwt.secret}") String secret, @Value("${jwt.expiration}") long expirationMs) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
    }

    public String generateToken(User user) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(user.getEmail())
                .claim("sessionVersion", user.getSessionVersion())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(signingKey)
                .compact();
    }

    public String extractEmail(String token) {
        return readSignedClaims(token).getSubject();
    }

    public TokenIdentity parseToken(String token) {
        Claims claims = readSignedClaims(token);
        String email = claims.getSubject();
        if (email == null || email.isBlank()) {
            throw new MalformedJwtException("Token subject is required");
        }
        if (claims.getExpiration() == null) {
            throw new MalformedJwtException("Token expiration is required");
        }

        Object version = claims.get("sessionVersion");
        if (!(version instanceof Integer || version instanceof Long)
                || ((Number) version).longValue() < 0) {
            throw new MalformedJwtException("Token session version must be a nonnegative integer");
        }
        return new TokenIdentity(email, ((Number) version).longValue());
    }

    private Claims readSignedClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public record TokenIdentity(String email, long sessionVersion) { }
}
