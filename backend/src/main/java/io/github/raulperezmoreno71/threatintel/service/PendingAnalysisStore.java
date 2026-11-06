package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisSnapshot;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.dto.PendingAnalysisResponse;
import io.github.raulperezmoreno71.threatintel.exception.PendingAnalysisException;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
public class PendingAnalysisStore {
    private final Duration ttl;
    private final int perUserLimit;
    private final int totalLimit;
    private final int maxSnapshotBytes;
    private final Clock clock;
    private final ObjectMapper mapper;
    private final Validator validator;
    private final Map<UUID, Entry> entries = new LinkedHashMap<>();

    @Autowired
    public PendingAnalysisStore(
            @Value("${app.analysis.drafts.ttl-seconds:900}") long ttlSeconds,
            @Value("${app.analysis.drafts.max-per-user:5}") int perUserLimit,
            @Value("${app.analysis.drafts.max-total:500}") int totalLimit,
            @Value("${app.analysis.drafts.max-snapshot-bytes:131072}") int maxSnapshotBytes,
            ObjectMapper mapper, Validator validator) {
        this(ttlSeconds, perUserLimit, totalLimit, maxSnapshotBytes, Clock.systemUTC(), mapper, validator);
    }

    public PendingAnalysisStore(long ttlSeconds, int perUserLimit, int totalLimit, int maxSnapshotBytes,
                                Clock clock, ObjectMapper mapper, Validator validator) {
        if (ttlSeconds <= 0 || perUserLimit <= 0 || totalLimit <= 0 || perUserLimit > totalLimit || maxSnapshotBytes <= 0) {
            throw new IllegalArgumentException("Pending analysis limits must be positive and per-user capacity must not exceed total capacity.");
        }
        this.ttl = Duration.ofSeconds(ttlSeconds);
        this.perUserLimit = perUserLimit;
        this.totalLimit = totalLimit;
        this.maxSnapshotBytes = maxSnapshotBytes;
        this.clock = Objects.requireNonNull(clock);
        this.mapper = mapper;
        this.validator = validator;
    }

    public PendingAnalysisResponse retain(Long ownerId, AnalyzeResponse report) {
        Objects.requireNonNull(ownerId);
        AnalysisSnapshot snapshot = mapper.convertValue(report, AnalysisSnapshot.class);
        byte[] bytes = mapper.writeValueAsBytes(snapshot);
        if (bytes.length > maxSnapshotBytes) {
            throw new PendingAnalysisException(HttpStatus.UNPROCESSABLE_ENTITY, "The generated report is too large to retain.");
        }
        UUID id = UUID.randomUUID();
        Instant expiresAt;
        synchronized (this) {
            removeExpired();
            long owned = entries.values().stream().filter(entry -> entry.ownerId.equals(ownerId)).count();
            if (owned >= perUserLimit) {
                UUID oldest = entries.entrySet().stream()
                        .filter(entry -> entry.getValue().ownerId.equals(ownerId) && !entry.getValue().claimed)
                        .map(Map.Entry::getKey).findFirst().orElseThrow(PendingAnalysisStore::capacityExceeded);
                entries.remove(oldest);
            }
            if (entries.size() >= totalLimit) {
                throw capacityExceeded();
            }
            expiresAt = clock.instant().plus(ttl);
            entries.put(id, new Entry(ownerId, bytes, expiresAt));
        }
        return new PendingAnalysisResponse(report, id, expiresAt);
    }

    public synchronized Claim claim(Long ownerId, UUID id) {
        removeExpired();
        Entry entry = entries.get(id);
        if (entry == null || !entry.ownerId.equals(ownerId) || !entry.expiresAt.isAfter(clock.instant())) {
            throw new PendingAnalysisException(HttpStatus.NOT_FOUND,
                    "Pending analysis unavailable or expired. Analyze the URL again.");
        }
        if (entry.claimed) {
            throw new PendingAnalysisException(HttpStatus.CONFLICT, "This analysis is already being saved. Please wait and check your history.");
        }
        entry.claimed = true;
        return new Claim(id, entry);
    }

    public AnalysisSnapshot snapshot(Claim claim) {
        return mapper.readValue(claim.entry.bytes, AnalysisSnapshot.class);
    }

    public void validateForPersistence(AnalysisSnapshot snapshot) {
        if (!validator.validate(snapshot).isEmpty()) {
            throw new PendingAnalysisException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "The generated report exceeds supported storage bounds and cannot be saved. Analyze another URL.");
        }
    }

    public synchronized void complete(Claim claim) {
        entries.remove(claim.id, claim.entry);
    }

    public synchronized void release(Claim claim) {
        if (entries.get(claim.id) == claim.entry) {
            claim.entry.claimed = false;
            if (!claim.entry.expiresAt.isAfter(clock.instant())) {
                entries.remove(claim.id);
            }
        }
    }

    @Scheduled(fixedDelay = 60_000)
    public synchronized void removeExpired() {
        Instant now = clock.instant();
        entries.values().removeIf(entry -> !entry.claimed && !entry.expiresAt.isAfter(now));
    }

    private static PendingAnalysisException capacityExceeded() {
        return new PendingAnalysisException(HttpStatus.SERVICE_UNAVAILABLE,
                "Temporary analysis storage is full. Please try again later.");
    }

    public static final class Claim {
        private final UUID id;
        private final Entry entry;
        private Claim(UUID id, Entry entry) { this.id = id; this.entry = entry; }
    }

    private static final class Entry {
        private final Long ownerId;
        private final byte[] bytes;
        private final Instant expiresAt;
        private boolean claimed;
        private Entry(Long ownerId, byte[] bytes, Instant expiresAt) {
            this.ownerId = ownerId;
            this.bytes = bytes;
            this.expiresAt = expiresAt;
        }
    }
}
