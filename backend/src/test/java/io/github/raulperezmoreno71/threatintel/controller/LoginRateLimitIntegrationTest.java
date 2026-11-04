package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.auth.LoginRequest;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.GlobalExceptionHandler;
import io.github.raulperezmoreno71.threatintel.exception.InvalidCredentialException;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.service.LoginRateLimitService;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Clock;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

// Real controller and advice; authentication and token creation are isolated.
// Security filters and session cookies are also covered by UserControllerTest.
class LoginRateLimitIntegrationTest {
    private static final Instant START = Instant.parse("2026-01-01T12:00:00Z");
    private MockMvc mockMvc;
    private UserService users;
    private JwtService jwt;
    private Clock clock;

    @BeforeEach
    void setUp() {
        clock = mock(Clock.class);
        when(clock.instant()).thenReturn(START);
        users = mock(UserService.class);
        jwt = mock(JwtService.class);
        when(users.login(any(LoginRequest.class)))
                .thenThrow(new InvalidCredentialException("Invalid email or password"));
        mockMvc = standaloneSetup(new UserController(users, jwt, new LoginRateLimitService(5, 300, clock)))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
    }

    @Test
    void rejectsSixthFailureBeforeCheckingCredentialsOrIssuingToken() throws Exception {
        failFiveTimes("user@example.com");
        login("user@example.com").andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "300"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"))
                .andExpect(jsonPath("$.path").value("/api/auth/login"))
                .andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(cookie().doesNotExist("access_token"));
        verify(users, times(5)).login(any(LoginRequest.class));
        verifyNoInteractions(jwt);
    }

    @Test
    void rejectedRequestsDoNotExtendTheWindowAndRetryAfterRoundsUp() throws Exception {
        failFiveTimes("user@example.com");
        when(clock.instant()).thenReturn(START.plusSeconds(299).plusMillis(500));
        login("user@example.com").andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "1"));
        when(clock.instant()).thenReturn(START.plusSeconds(300));
        login("user@example.com").andExpect(status().isUnauthorized());
        verify(users, times(6)).login(any(LoginRequest.class));
    }

    @Test
    void successfulLoginClearsPreviousFailures() throws Exception {
        for (int i = 0; i < 4; i++) login("user@example.com").andExpect(status().isUnauthorized());
        User account = new User("user@example.com", "hash", UserStatus.ACTIVE);
        when(users.login(any(LoginRequest.class))).thenReturn(account);
        when(jwt.generateToken(account)).thenReturn("signed-token");
        login("user@example.com").andExpect(status().isOk())
                .andExpect(cookie().value("access_token", "signed-token"));
        when(users.login(any(LoginRequest.class)))
                .thenThrow(new InvalidCredentialException("Invalid email or password"));
        failFiveTimes("user@example.com");
        login("user@example.com").andExpect(status().isTooManyRequests());
    }

    @Test
    void keepsDifferentEmailsIndependent() throws Exception {
        failFiveTimes("first@example.com");
        login("first@example.com").andExpect(status().isTooManyRequests());
        login("second@example.com").andExpect(status().isUnauthorized());
    }

    @Test
    void internalFailuresReleaseReservationsWithoutCountingAsBadPasswords() throws Exception {
        when(users.login(any(LoginRequest.class))).thenThrow(new IllegalStateException("Authentication unavailable"));
        for (int i = 0; i < 6; i++) login("user@example.com").andExpect(status().isInternalServerError());
        when(users.login(any(LoginRequest.class)))
                .thenThrow(new InvalidCredentialException("Invalid email or password"));
        failFiveTimes("user@example.com");
        login("user@example.com").andExpect(status().isTooManyRequests());
    }

    @Test
    void invalidBodiesAreRejectedBeforeConsumingQuota() throws Exception {
        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"email\":\"user@example.com\",\"password\":\"\"}"))
                    .andExpect(status().isBadRequest());
        }
        verifyNoInteractions(users, jwt);
        failFiveTimes("user@example.com");
        login("user@example.com").andExpect(status().isTooManyRequests());
    }

    private void failFiveTimes(String email) throws Exception {
        for (int i = 0; i < 5; i++) login(email).andExpect(status().isUnauthorized());
    }

    private ResultActions login(String email) throws Exception {
        return mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"wrong-password\"}"));
    }
}
