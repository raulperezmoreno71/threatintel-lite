package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import io.github.raulperezmoreno71.threatintel.exception.DnsResolverBusyException;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DnsDeadlineTest {

    @Test
    void shouldStopWaitingEvenWhenNativeLookupIgnoresInterruption() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        var workers = resolverPool();
        var callers = Executors.newSingleThreadExecutor();
        try {
            DnsAnalyzer analyzer = spy(new DnsAnalyzer(workers));
            doAnswer(invocation -> {
                started.countDown();
                while (release.getCount() != 0) {
                    try {
                        release.await();
                    } catch (InterruptedException ignored) {
                        // Model an operating-system resolver that cannot be interrupted.
                    }
                }
                return new InetAddress[]{InetAddress.getByName("8.8.8.8")};
            }).when(analyzer).resolve("example.com");
            var request = callers.submit(() -> analyzer.resolve("example.com", AnalysisDeadline.start(Duration.ofMillis(200))));
            assertTrue(started.await(2, TimeUnit.SECONDS));

            ExecutionException failure = assertThrows(ExecutionException.class, () -> request.get(2, TimeUnit.SECONDS));

            assertInstanceOf(AnalysisTimeoutException.class, failure.getCause());
            assertEquals(1, workers.getActiveCount());
        } finally {
            release.countDown();
            callers.shutdownNow();
            workers.shutdownNow();
            assertTrue(callers.awaitTermination(2, TimeUnit.SECONDS));
            assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS));
        }
    }

    @Test
    void shouldRejectNewLookupsWhenWorkersAndQueueAreFull() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        var workers = resolverPool();
        try {
            workers.submit(() -> {
                started.countDown();
                release.await();
                return null;
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            workers.submit(() -> null);
            DnsAnalyzer analyzer = new DnsAnalyzer(workers);

            assertThrows(DnsResolverBusyException.class,
                    () -> analyzer.resolve("example.com", AnalysisDeadline.startDefault()));
        } finally {
            release.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS));
        }
    }

    @Test
    void shouldRemoveExpiredQueuedLookups() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        var workers = resolverPool();
        try {
            workers.submit(() -> {
                started.countDown();
                release.await();
                return null;
            });
            assertTrue(started.await(2, TimeUnit.SECONDS));
            DnsAnalyzer analyzer = new DnsAnalyzer(workers);

            assertThrows(AnalysisTimeoutException.class,
                    () -> analyzer.resolve("example.com", AnalysisDeadline.start(Duration.ofMillis(50))));

            assertTrue(workers.getQueue().isEmpty());
        } finally {
            release.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS));
        }
    }

    private ThreadPoolExecutor resolverPool() {
        return new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(1));
    }
}
