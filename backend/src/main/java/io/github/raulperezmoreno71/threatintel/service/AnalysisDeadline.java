package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Duration;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

public final class AnalysisDeadline {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisDeadline.class);
    private static final ScheduledThreadPoolExecutor cancellations = cancellationExecutor();
    private final long budgetNanos;
    private final long startedAt;
    private final LongSupplier ticker;

    AnalysisDeadline(Duration duration, LongSupplier ticker) {
        budgetNanos = duration.toNanos();
        if (budgetNanos <= 0) {
            throw new IllegalArgumentException("Analysis timeout must be positive");
        }
        this.ticker = ticker;
        startedAt = ticker.getAsLong();
    }

    public static AnalysisDeadline start(Duration duration) {
        return new AnalysisDeadline(duration, System::nanoTime);
    }

    public static AnalysisDeadline startDefault() {
        return start(Duration.ofSeconds(15));
    }

    public long remainingNanos() {
        long remaining = budgetNanos - (ticker.getAsLong() - startedAt);
        if (remaining <= 0) {
            throw new AnalysisTimeoutException();
        }
        return remaining;
    }

    public int timeoutMillis(int maximumMillis) {
        if (maximumMillis <= 0) {
            throw new IllegalArgumentException("Operation timeout must be positive");
        }
        long nanos = remainingNanos();
        long milliseconds = nanos / 1_000_000 + (nanos % 1_000_000 == 0 ? 0 : 1);
        return (int) Math.min(maximumMillis, milliseconds);
    }

    public void check() {
        remainingNanos();
    }

    public Cancellation abortOnTimeout(Runnable abort) {
        AtomicBoolean active = new AtomicBoolean(true);
        var task = cancellations.schedule(() -> {
            if (active.compareAndSet(true, false)) {
                try {
                    abort.run();
                } catch (RuntimeException failure) {
                    logger.warn("Could not abort an expired analysis operation", failure);
                }
            }
        }, remainingNanos(), TimeUnit.NANOSECONDS);
        return () -> {
            active.set(false);
            task.cancel(false);
        };
    }

    private static ScheduledThreadPoolExecutor cancellationExecutor() {
        var executor = new ScheduledThreadPoolExecutor(2, task -> {
            Thread thread = new Thread(task, "analysis-deadline");
            thread.setDaemon(true);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
        return executor;
    }

    public interface Cancellation extends AutoCloseable {
        @Override
        void close();
    }
}
