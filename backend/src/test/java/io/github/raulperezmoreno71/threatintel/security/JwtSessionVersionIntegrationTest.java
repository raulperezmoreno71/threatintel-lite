package io.github.raulperezmoreno71.threatintel.security;

import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import tools.jackson.databind.json.JsonMapper;

import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtSessionVersionIntegrationTest {
    private static final String SECRET = "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=";
    private JwtService jwtService;
    private UserRepository users;
    private JwtAuthenticationFilter filter;
    private User user;

    @BeforeEach
    void setUp() {
        jwtService = spy(new JwtService(SECRET, 3600000));
        users = mock(UserRepository.class);
        user = new User("user@example.com", "hash", UserStatus.ACTIVE);
        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        filter = new JwtAuthenticationFilter(jwtService,
                new CustomAuthenticationEntryPoint(JsonMapper.builder().build()), users);
    }

    @AfterEach
    void clearAuthentication() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void checksStoredVersionOnEveryRequestAndAcceptsANewTokenAfterRevocation() throws Exception {
        String oldToken = jwtService.generateToken(user);
        assertEquals(200, request(oldToken, "/api/auth/me").getStatus());
        user.incrementSessionVersion();
        assertUnauthorized(request(oldToken, "/api/auth/me"));
        assertEquals(200, request(jwtService.generateToken(user), "/api/auth/me").getStatus());
        verify(users, times(3)).findByEmail("user@example.com");
    }

    @Test
    void rejectsAValidTokenWhenItsUserNoLongerExists() throws Exception {
        when(users.findByEmail("user@example.com")).thenReturn(Optional.empty());
        assertUnauthorized(request(jwtService.generateToken(user), "/api/auth/me"));
    }

    @ParameterizedTest
    @EnumSource(value = UserStatus.class, names = {"DISABLED", "LOCKED"})
    void rejectsInactiveUsers(UserStatus state) throws Exception {
        String token = jwtService.generateToken(user);
        when(users.findByEmail("user@example.com"))
                .thenReturn(Optional.of(new User("user@example.com", "hash", state)));
        assertUnauthorized(request(token, "/api/auth/me"));
    }

    @Test
    void rejectsLegacyTokensWithoutVersionBeforeQueryingTheDatabase() throws Exception {
        String token = Jwts.builder().subject("user@example.com")
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET))).compact();
        assertUnauthorized(request(token, "/api/auth/me"));
        verifyNoInteractions(users);
    }

    @Test
    void rejectsWrongSignaturesBeforeQueryingTheDatabase() throws Exception {
        JwtService otherSigner = new JwtService("y/EAFsHOGmJdElwFjzi/2CsPUilZGiDOhcftfcNh2gY=", 3600000);
        assertUnauthorized(request(otherSigner.generateToken(user), "/api/auth/me"));
        verifyNoInteractions(users);
    }

    @Test
    void verifiesTheJwtAndLooksUpTheUserOnlyOncePerRequest() throws Exception {
        String token = jwtService.generateToken(user);
        assertEquals(200, request(token, "/api/auth/me").getStatus());
        verify(jwtService).parseToken(token);
        verify(jwtService, never()).extractEmail(anyString());
        verify(users).findByEmail("user@example.com");
    }

    @Test
    void databaseFailuresDoNotAuthenticateOrMasqueradeAsInvalidCredentials() {
        String token = jwtService.generateToken(user);
        var unavailable = new DataAccessResourceFailureException("Database unavailable");
        when(users.findByEmail("user@example.com")).thenThrow(unavailable);
        assertSame(unavailable, assertThrows(DataAccessResourceFailureException.class,
                () -> request(token, "/api/auth/me")));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/api/auth/login", "/api/auth/register", "/api/auth/logout", "/api/health"})
    void publicEndpointsRemainAccessibleWithOldCookies(String path) throws Exception {
        assertEquals(200, request("old-or-invalid-token", path).getStatus());
        verifyNoInteractions(users, jwtService);
    }

    private MockHttpServletResponse request(String token, String path) throws Exception {
        SecurityContextHolder.clearContext();
        var request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        request.setCookies(new Cookie("access_token", token));
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (incoming, outgoing) -> response.setStatus(200));
        return response;
    }

    private void assertUnauthorized(MockHttpServletResponse response) throws Exception {
        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        var body = JsonMapper.builder().build().readTree(response.getContentAsString());
        assertEquals(401, body.get("status").asInt());
        assertEquals("Authentication is required", body.get("message").asString());
    }
}
