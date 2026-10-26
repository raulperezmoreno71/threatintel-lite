package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class AnalysisDeadlineTest {

    @Test
    void shouldShareElapsedTimeAcrossOperations() {
        AtomicLong ticker = new AtomicLong();
        AnalysisDeadline deadline = new AnalysisDeadline(Duration.ofSeconds(15), ticker::get);

        ticker.set(Duration.ofSeconds(5).toNanos());
        assertEquals(Duration.ofSeconds(10).toNanos(), deadline.remainingNanos());
        assertEquals(5000, deadline.timeoutMillis(5000));

        ticker.set(Duration.ofSeconds(14).toNanos());
        assertEquals(1000, deadline.timeoutMillis(5000));
    }

    @Test
    void shouldRejectOperationsAtTheDeadline() {
        AtomicLong ticker = new AtomicLong();
        AnalysisDeadline deadline = new AnalysisDeadline(Duration.ofSeconds(15), ticker::get);
        ticker.set(Duration.ofSeconds(15).toNanos());

        assertThrows(AnalysisTimeoutException.class, deadline::check);
        assertThrows(AnalysisTimeoutException.class, () -> deadline.timeoutMillis(5000));
    }

    @Test
    void shouldNeverConvertPositiveTimeToAnUnlimitedZeroTimeout() {
        AnalysisDeadline deadline = new AnalysisDeadline(Duration.ofNanos(1), () -> 0);

        assertEquals(1, deadline.timeoutMillis(5000));
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void shouldRejectNonPositiveBudgets(long milliseconds) {
        assertThrows(IllegalArgumentException.class, () -> AnalysisDeadline.start(Duration.ofMillis(milliseconds)));
    }

    @Test
    void shouldAbortAnActiveOperationWhenTimeExpires() throws Exception {
        CountDownLatch aborted = new CountDownLatch(1);
        AnalysisDeadline deadline = AnalysisDeadline.start(Duration.ofMillis(50));

        try (var cancellation = deadline.abortOnTimeout(aborted::countDown)) {
            assertTrue(aborted.await(2, TimeUnit.SECONDS));
            assertThrows(AnalysisTimeoutException.class, deadline::check);
        }
    }

    @Test
    void shouldRemoveCancellationWhenOperationCompletes() throws Exception {
        CountDownLatch aborted = new CountDownLatch(1);
        AnalysisDeadline deadline = AnalysisDeadline.start(Duration.ofMillis(50));

        var cancellation = deadline.abortOnTimeout(aborted::countDown);
        cancellation.close();

        assertFalse(aborted.await(150, TimeUnit.MILLISECONDS));
    }
}
