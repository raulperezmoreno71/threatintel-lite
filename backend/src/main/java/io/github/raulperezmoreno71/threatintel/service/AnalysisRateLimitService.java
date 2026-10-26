package io.github.raulperezmoreno71.threatintel.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

@Service
public class AnalysisRateLimitService {

    private final Clock clock;
    private final int maxRequests;
    private final Duration window;
    private final Map<Long, Deque<Instant>> attemptsByUser = new HashMap<>();

    @Autowired
    public AnalysisRateLimitService(
            @Value("${app.analysis.rate-limit.max-requests}") int maxRequests,
            @Value("${app.analysis.rate-limit.window-seconds}") long windowSeconds
    ) {
        this(maxRequests, windowSeconds, Clock.systemUTC());
    }

    public AnalysisRateLimitService (
            int maxRequests,
            long windowSeconds,
            Clock clock
    ) {
        if (maxRequests <= 0 || windowSeconds <= 0) {
            throw new IllegalArgumentException("Analysis rate limit configuration must be positive.");
        }

        this.maxRequests = maxRequests;
        this.window = Duration.ofSeconds(windowSeconds);
        this.clock = clock;
    }

    public synchronized boolean tryAcquire(Long userId) {
        Instant now = Instant.now(clock);
        Instant cutOff = now.minus(window);

        Deque<Instant> attempts = attemptsByUser.computeIfAbsent(userId, ignore -> new ArrayDeque<>());

        while (!attempts.isEmpty() && !attempts.peekFirst().isAfter(cutOff)) {
            attempts.removeFirst();
        }

        if (attempts.size() >= maxRequests) {
            return false;
        }

        attempts.addLast(now);
        return true;
    }

    @Scheduled(fixedDelay = 60_000)
    public synchronized void removeInactiveUsers() {
        Instant cutOff = Instant.now(clock).minus(window);

        attemptsByUser.entrySet().removeIf(entry -> {
            Deque<Instant> attempts = entry.getValue();

            return attempts.isEmpty() || !attempts.peekLast().isAfter(cutOff);
        });
    }
}
