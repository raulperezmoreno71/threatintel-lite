package io.github.raulperezmoreno71.threatintel.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class AnalysisRateLimitServiceTest {

    private static final Instant START = Instant.parse("2026-01-01T12:00:00Z");

    private AdjustableClock clock;
    private AnalysisRateLimitService service;

    @BeforeEach
    void setUp() {
        clock = new AdjustableClock(START);
        service = new AnalysisRateLimitService(5, 60, clock);
    }

    @ParameterizedTest
    @CsvSource({"0, 60", "-1, 60", "5, 0", "5, -1"})
    void shouldRejectNonPositiveConfiguration(int maxRequests, long windowSeconds) {
        assertThrows(IllegalArgumentException.class,
                () -> new AnalysisRateLimitService(maxRequests, windowSeconds, clock));
    }

    @Test
    void shouldRejectRequestsAfterReachingLimit() {
        for (int i = 0; i < 5; i++) {
            assertTrue(service.tryAcquire(1L));
        }

        assertFalse(service.tryAcquire(1L));
        assertFalse(service.tryAcquire(1L));
    }

    @Test
    void shouldKeepLimitsIndependentForEachUser() {
        for (int i = 0; i < 5; i++) {
            assertTrue(service.tryAcquire(1L));
            assertTrue(service.tryAcquire(2L));
        }

        assertFalse(service.tryAcquire(1L));
        assertFalse(service.tryAcquire(2L));
        assertTrue(service.tryAcquire(3L));
    }

    @Test
    void shouldExpireAttemptsExactlyAtWindowBoundaryWithoutScheduledCleanup() {
        for (int i = 0; i < 5; i++) {
            assertTrue(service.tryAcquire(1L));
        }

        clock.set(START.plusSeconds(60).minusNanos(1));
        assertFalse(service.tryAcquire(1L));

        clock.set(START.plusSeconds(60));
        for (int i = 0; i < 5; i++) {
            assertTrue(service.tryAcquire(1L));
        }
        assertFalse(service.tryAcquire(1L));
    }

    @Test
    void shouldExpireOnlyAttemptsOutsideSlidingWindow() {
        service = new AnalysisRateLimitService(2, 60, clock);
        assertTrue(service.tryAcquire(1L));

        clock.set(START.plusSeconds(30));
        assertTrue(service.tryAcquire(1L));
        assertFalse(service.tryAcquire(1L));

        clock.set(START.plusSeconds(60));
        assertTrue(service.tryAcquire(1L));
        assertFalse(service.tryAcquire(1L));

        clock.set(START.plusSeconds(90));
        assertTrue(service.tryAcquire(1L));
        assertFalse(service.tryAcquire(1L));
    }

    @Test
    void shouldNotExtendWindowWhenRequestsAreRejected() {
        service = new AnalysisRateLimitService(1, 60, clock);
        assertTrue(service.tryAcquire(1L));

        clock.set(START.plusSeconds(59));
        assertFalse(service.tryAcquire(1L));

        clock.set(START.plusSeconds(60));
        assertTrue(service.tryAcquire(1L));
        assertFalse(service.tryAcquire(1L));
    }

    @Test
    void shouldRemoveEveryInactiveUserAtWindowBoundary() {
        assertTrue(service.tryAcquire(1L));
        assertTrue(service.tryAcquire(2L));
        assertTrue(service.tryAcquire(3L));

        clock.set(START.plusSeconds(60));
        service.removeInactiveUsers();

        // Admission alone cannot prove that unused entries release their memory.
        assertTrue(trackedUsers().isEmpty());
        assertTrue(service.tryAcquire(1L));
    }

    @Test
    void shouldKeepUsersWithRecentAttemptsDuringCleanup() {
        service = new AnalysisRateLimitService(2, 60, clock);
        assertTrue(service.tryAcquire(1L));
        assertTrue(service.tryAcquire(2L));

        clock.set(START.plusSeconds(30));
        assertTrue(service.tryAcquire(2L));

        clock.set(START.plusSeconds(60));
        service.removeInactiveUsers();

        assertFalse(trackedUsers().containsKey(1L));
        assertTrue(trackedUsers().containsKey(2L));
        assertTrue(service.tryAcquire(2L));
        assertFalse(service.tryAcquire(2L));
    }

    @Test
    void shouldKeepActiveLimitsAcrossRepeatedCleanup() {
        service = new AnalysisRateLimitService(1, 60, clock);
        assertTrue(service.tryAcquire(1L));

        service.removeInactiveUsers();
        service.removeInactiveUsers();

        assertFalse(service.tryAcquire(1L));
    }

    @Test
    void shouldHandleCleanupWithoutTrackedUsers() {
        assertDoesNotThrow(service::removeInactiveUsers);
        assertTrue(service.tryAcquire(1L));
    }

    @Test
    void shouldAdmitExactlyFiveSimultaneousRequestsForSameUser() throws Exception {
        int requestCount = 24;
        CountDownLatch ready = new CountDownLatch(requestCount);
        CountDownLatch start = new CountDownLatch(1);

        try (var executor = Executors.newFixedThreadPool(requestCount)) {
            var results = new ArrayList<Future<Boolean>>();
            try {
                for (int i = 0; i < requestCount; i++) {
                    results.add(executor.submit(() -> {
                        ready.countDown();
                        if (!start.await(5, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Timed out waiting to start requests");
                        }
                        return service.tryAcquire(1L);
                    }));
                }
                assertTrue(ready.await(5, TimeUnit.SECONDS));
            } finally {
                start.countDown();
            }

            int admitted = 0;
            for (Future<Boolean> result : results) {
                if (result.get(5, TimeUnit.SECONDS)) {
                    admitted++;
                }
            }

            assertEquals(5, admitted);
            assertFalse(service.tryAcquire(1L));
            assertTrue(service.tryAcquire(2L));
        }
    }

    private Map<?, ?> trackedUsers() {
        return (Map<?, ?>) ReflectionTestUtils.getField(service, "attemptsByUser");
    }

    private static class AdjustableClock extends Clock {

        private final AtomicReference<Instant> current;
        private final ZoneId zone;

        AdjustableClock(Instant initial) {
            this(new AtomicReference<>(initial), ZoneOffset.UTC);
        }

        private AdjustableClock(AtomicReference<Instant> current, ZoneId zone) {
            this.current = current;
            this.zone = zone;
        }

        void set(Instant instant) {
            current.set(instant);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new AdjustableClock(current, zone);
        }

        @Override
        public Instant instant() {
            return current.get();
        }
    }
}
