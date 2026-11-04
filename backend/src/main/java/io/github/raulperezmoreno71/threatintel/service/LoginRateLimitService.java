package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.LoginRateLimitExceededException;
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
import java.util.Objects;

@Service
public class LoginRateLimitService {
    private final int maxFailures;
    private final Duration window;
    private final Clock clock;
    private final Map<String, EmailAttempts> attemptsByEmail = new HashMap<>();

    @Autowired
    public LoginRateLimitService(
            @Value("${app.auth.login.rate-limit.max-failures}") int maxFailures,
            @Value("${app.auth.login.rate-limit.window-seconds}") long windowSeconds) {
        this(maxFailures, windowSeconds, Clock.systemUTC());
    }

    public LoginRateLimitService(int maxFailures, long windowSeconds, Clock clock) {
        if (maxFailures <= 0 || windowSeconds <= 0) {
            throw new IllegalArgumentException("Login rate limit configuration must be positive.");
        }
        this.maxFailures = maxFailures;
        this.window = Duration.ofSeconds(windowSeconds);
        this.clock = Objects.requireNonNull(clock);
    }

    public synchronized Attempt acquire(String email) {
        Objects.requireNonNull(email);
        Instant now = clock.instant();
        EmailAttempts state = attemptsByEmail.computeIfAbsent(email, ignored -> new EmailAttempts());
        expireFailures(state, now);
        if (state.failures.size() + state.inFlight >= maxFailures) {
            throw new LoginRateLimitExceededException(retryAfterSeconds(state, now));
        }
        state.inFlight++;
        return new Attempt(email, state, state.generation);
    }

    private synchronized void finish(Attempt attempt, Outcome outcome) {
        if (attempt.finished) return;
        attempt.finished = true;
        EmailAttempts state = attempt.state;
        state.inFlight--;
        expireFailures(state, clock.instant());
        if (outcome == Outcome.SUCCESS) {
            state.failures.clear();
            state.generation++;
        } else if (outcome == Outcome.FAILURE && attempt.generation == state.generation) {
            state.failures.addLast(clock.instant());
        }
        if (state.inFlight == 0 && state.failures.isEmpty()) {
            attemptsByEmail.remove(attempt.email, state);
        }
    }

    private void expireFailures(EmailAttempts state, Instant now) {
        Instant cutoff = now.minus(window);
        while (!state.failures.isEmpty() && !state.failures.peekFirst().isAfter(cutoff)) {
            state.failures.removeFirst();
        }
    }

    private long retryAfterSeconds(EmailAttempts state, Instant now) {
        if (state.failures.isEmpty()) return 1;
        Duration remaining = Duration.between(now, state.failures.peekFirst().plus(window));
        return Math.max(1, remaining.getSeconds() + (remaining.getNano() == 0 ? 0 : 1));
    }

    @Scheduled(fixedDelay = 60_000)
    public synchronized void removeInactiveEmails() {
        Instant now = clock.instant();
        attemptsByEmail.entrySet().removeIf(entry -> {
            EmailAttempts state = entry.getValue();
            expireFailures(state, now);
            return state.inFlight == 0 && state.failures.isEmpty();
        });
    }

    private enum Outcome { SUCCESS, FAILURE, RELEASE }

    private static final class EmailAttempts {
        private final Deque<Instant> failures = new ArrayDeque<>();
        private int inFlight;
        private long generation;
    }

    public final class Attempt implements AutoCloseable {
        private final String email;
        private final EmailAttempts state;
        private final long generation;
        private boolean finished;

        private Attempt(String email, EmailAttempts state, long generation) {
            this.email = email;
            this.state = state;
            this.generation = generation;
        }

        public void succeeded() { finish(this, Outcome.SUCCESS); }
        public void failed() { finish(this, Outcome.FAILURE); }

        @Override
        public void close() { finish(this, Outcome.RELEASE); }
    }
}
