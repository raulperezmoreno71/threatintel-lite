package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.LoginRateLimitExceededException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LoginRateLimitServiceTest {
    private static final Instant START = Instant.parse("2026-01-01T12:00:00Z");
    private Clock clock;
    private LoginRateLimitService limiter;

    @BeforeEach
    void setUp() {
        clock = mock(Clock.class);
        when(clock.instant()).thenReturn(START);
        limiter = new LoginRateLimitService(5, 300, clock);
    }

    @ParameterizedTest
    @CsvSource({"0,300", "-1,300", "5,0", "5,-1"})
    void rejectsInvalidConfiguration(int limit, long seconds) {
        assertThrows(IllegalArgumentException.class, () -> new LoginRateLimitService(limit, seconds, clock));
    }

    @Test
    void blocksAfterFiveFailuresAndKeepsEmailsIndependent() {
        failFiveTimes("first@example.com");
        assertEquals(300, assertThrows(LoginRateLimitExceededException.class,
                () -> limiter.acquire("first@example.com")).getRetryAfterSeconds());
        try (var attempt = limiter.acquire("second@example.com")) {
            attempt.succeeded();
        }
    }

    @Test
    void usesExactEmailKeysLikeTheCurrentAuthenticationLookup() {
        failFiveTimes("User@example.com");
        try (var ignored = limiter.acquire("user@example.com")) {
            assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("User@example.com"));
        }
    }

    @Test
    void releasesAbortedAttemptsWithoutAddingFailures() {
        for (int i = 0; i < 20; i++) {
            try (var ignored = limiter.acquire("user@example.com")) { }
        }
        failFiveTimes("user@example.com");
        assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("user@example.com"));
    }

    @Test
    void completingAnAttemptTwiceDoesNotConsumeAnotherSlotOrClearFailures() {
        var attempt = limiter.acquire("user@example.com");
        attempt.failed();
        attempt.failed();
        attempt.succeeded();
        attempt.close();
        for (int i = 0; i < 4; i++) limiter.acquire("user@example.com").failed();
        assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("user@example.com"));
    }

    @Test
    void expiresFailuresAtTheExactBoundaryAndRoundsRetryAfterUp() {
        failFiveTimes("user@example.com");
        when(clock.instant()).thenReturn(START.plusSeconds(300).minusNanos(1));
        assertEquals(1, assertThrows(LoginRateLimitExceededException.class,
                () -> limiter.acquire("user@example.com")).getRetryAfterSeconds());
        when(clock.instant()).thenReturn(START.plusSeconds(300));
        try (var ignored = limiter.acquire("user@example.com")) { }
    }

    @Test
    void expiresIndividualFailuresRatherThanResettingTheWholeWindow() {
        for (int i = 0; i < 5; i++) {
            when(clock.instant()).thenReturn(START.plusSeconds(i * 30L));
            limiter.acquire("user@example.com").failed();
        }
        when(clock.instant()).thenReturn(START.plusSeconds(300));
        limiter.acquire("user@example.com").failed();
        assertEquals(30, assertThrows(LoginRateLimitExceededException.class,
                () -> limiter.acquire("user@example.com")).getRetryAfterSeconds());
        when(clock.instant()).thenReturn(START.plusSeconds(301));
        assertEquals(29, assertThrows(LoginRateLimitExceededException.class,
                () -> limiter.acquire("user@example.com")).getRetryAfterSeconds());
    }

    @Test
    void successfulAuthenticationClearsFailuresIncludingOlderPendingAttempts() {
        for (int i = 0; i < 3; i++) limiter.acquire("user@example.com").failed();
        var olderAttempt = limiter.acquire("user@example.com");
        var successfulAttempt = limiter.acquire("user@example.com");
        successfulAttempt.succeeded();
        olderAttempt.failed();
        for (int i = 0; i < 4; i++) limiter.acquire("user@example.com").failed();
        try (var lastAllowed = limiter.acquire("user@example.com")) {
            lastAllowed.failed();
        }
        assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("user@example.com"));
    }

    @Test
    void successDoesNotEraseOtherRequestsStillInFlight() {
        List<LoginRateLimitService.Attempt> attempts = new ArrayList<>();
        for (int i = 0; i < 5; i++) attempts.add(limiter.acquire("user@example.com"));
        attempts.getFirst().succeeded();
        try (var ignored = limiter.acquire("user@example.com")) {
            assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("user@example.com"));
        } finally {
            attempts.forEach(LoginRateLimitService.Attempt::close);
        }
    }

    @Test
    void concurrentRequestsCannotReserveMoreThanFiveSlots() throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        List<LoginRateLimitService.Attempt> admitted = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(8)) {
            List<Future<LoginRateLimitService.Attempt>> results = new ArrayList<>();
            for (int i = 0; i < 32; i++) {
                results.add(executor.submit(() -> {
                    start.await();
                    try {
                        return limiter.acquire("user@example.com");
                    } catch (LoginRateLimitExceededException rejected) {
                        return null;
                    }
                }));
            }
            start.countDown();
            for (var result : results) {
                var attempt = result.get(5, TimeUnit.SECONDS);
                if (attempt != null) admitted.add(attempt);
            }
            assertEquals(5, admitted.size());
            assertEquals(1, assertThrows(LoginRateLimitExceededException.class,
                    () -> limiter.acquire("user@example.com")).getRetryAfterSeconds());
        } finally {
            admitted.forEach(LoginRateLimitService.Attempt::close);
        }
        try (var ignored = limiter.acquire("user@example.com")) { }
    }

    @Test
    void cleanupRetainsActiveReservationsEvenAfterTheFailureWindow() {
        List<LoginRateLimitService.Attempt> pending = new ArrayList<>();
        for (int i = 0; i < 5; i++) pending.add(limiter.acquire("user@example.com"));
        when(clock.instant()).thenReturn(START.plusSeconds(600));
        limiter.removeInactiveEmails();
        assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("user@example.com"));
        pending.forEach(LoginRateLimitService.Attempt::close);
        try (var ignored = limiter.acquire("user@example.com")) { }
    }

    @Test
    void cleanupRemovesExpiredEmailStateButPreservesUnexpiredFailures() {
        failFiveTimes("user@example.com");
        when(clock.instant()).thenReturn(START.plusSeconds(299));
        limiter.removeInactiveEmails();
        assertThrows(LoginRateLimitExceededException.class, () -> limiter.acquire("user@example.com"));
        when(clock.instant()).thenReturn(START.plusSeconds(300));
        limiter.removeInactiveEmails();
        Map<?, ?> storedEmails = (Map<?, ?>) ReflectionTestUtils.getField(limiter, "attemptsByEmail");
        assertNotNull(storedEmails);
        assertTrue(storedEmails.isEmpty(), "Expired email state must not accumulate in memory");
    }

    private void failFiveTimes(String email) {
        for (int i = 0; i < 5; i++) limiter.acquire(email).failed();
    }
}
