package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.*;
import io.github.raulperezmoreno71.threatintel.exception.PendingAnalysisException;
import jakarta.validation.Validation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import tools.jackson.databind.json.JsonMapper;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static io.github.raulperezmoreno71.threatintel.support.AnalysisFixtures.report;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PendingAnalysisStoreTest {
    private static final Instant START = Instant.parse("2026-01-01T12:00:00Z");
    private final Clock clock = mock(Clock.class);
    private final JsonMapper mapper = JsonMapper.builder().findAndAddModules().build();
    private PendingAnalysisStore store;

    @BeforeEach void setup() {
        when(clock.instant()).thenReturn(START);
        store = store(2, 3, 131072);
    }

    private PendingAnalysisStore store(int perUser, int total, int bytes) {
        return new PendingAnalysisStore(900, perUser, total, bytes, clock, mapper,
                Validation.buildDefaultValidatorFactory().getValidator());
    }

    @Test void retainsImmutableSnapshotWithRandomIdentifierAndExpiry() {
        AnalyzeResponse original = report(null);
        PendingAnalysisResponse response = store.retain(42L, original);
        assertNotNull(response.getPendingAnalysisId());
        assertEquals(START.plusSeconds(900), response.getExpiresAt());
        original.setUrl("https://forged.example");
        original.getSecurityAssessment().setScore(0);
        original.getSecurityHeaders().getContentSecurityPolicy().setValue("forged");
        var claim = store.claim(42L, response.getPendingAnalysisId());
        var snapshot = store.snapshot(claim);
        assertEquals("https://example.com", snapshot.getUrl());
        assertEquals(100, snapshot.getSecurityAssessment().getScore());
        assertEquals("valid-value", snapshot.getSecurityHeaders().getContentSecurityPolicy().getValue());
        snapshot.setUrl("changed-again");
        assertEquals("https://example.com", store.snapshot(claim).getUrl());
        store.release(claim);
        assertNotEquals(response.getPendingAnalysisId(), store.retain(42L, report(null)).getPendingAnalysisId());
    }

    @Test void rejectsOtherOwnerWithoutConsumingOrRevealingDraft() {
        UUID id = store.retain(1L, report(null)).getPendingAnalysisId();
        var other = assertThrows(PendingAnalysisException.class, () -> store.claim(2L, id));
        var unknown = assertThrows(PendingAnalysisException.class, () -> store.claim(2L, UUID.randomUUID()));
        assertEquals(HttpStatus.NOT_FOUND, other.getStatus());
        assertEquals(unknown.getMessage(), other.getMessage());
        assertNotNull(store.claim(1L, id));
    }

    @Test void expiresAtExactTtlAndCleansUpCapacity() {
        UUID id = store.retain(1L, report(null)).getPendingAnalysisId();
        store.retain(2L, report(null));
        store.retain(3L, report(null));
        when(clock.instant()).thenReturn(START.plusSeconds(900).minusNanos(1));
        var claim = store.claim(1L, id);
        store.release(claim);
        when(clock.instant()).thenReturn(START.plusSeconds(900));
        assertEquals(HttpStatus.NOT_FOUND, assertThrows(PendingAnalysisException.class, () -> store.claim(1L, id)).getStatus());
        store.removeExpired();
        assertNotNull(store.retain(4L, report(null)));
        assertNotNull(store.retain(5L, report(null)));
        assertNotNull(store.retain(6L, report(null)));
    }

    @Test void evictsOnlyOldestUnclaimedDraftOfSameOwner() {
        UUID first = store.retain(1L, report(null)).getPendingAnalysisId();
        UUID second = store.retain(1L, report(null)).getPendingAnalysisId();
        var claim = store.claim(1L, first);
        UUID third = store.retain(1L, report(null)).getPendingAnalysisId();
        assertThrows(PendingAnalysisException.class, () -> store.claim(1L, second));
        assertEquals(HttpStatus.CONFLICT, assertThrows(PendingAnalysisException.class, () -> store.claim(1L, first)).getStatus());
        store.complete(claim);
        assertNotNull(store.claim(1L, third));
    }

    @Test void fullGlobalStoreRejectsWithoutEvictingOtherOwners() {
        UUID first = store.retain(1L, report(null)).getPendingAnalysisId();
        store.retain(2L, report(null));
        store.retain(3L, report(null));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(PendingAnalysisException.class,
                () -> store.retain(4L, report(null))).getStatus());
        assertNotNull(store.claim(1L, first));
    }

    @Test void keepsExpiredInFlightClaimsCountedAndReleasesThemAfterFailure() {
        store = store(1, 1, 131072);
        UUID id = store.retain(1L, report(null)).getPendingAnalysisId();
        var claim = store.claim(1L, id);
        when(clock.instant()).thenReturn(START.plusSeconds(901));
        store.removeExpired();
        assertThrows(PendingAnalysisException.class, () -> store.retain(2L, report(null)));
        assertThrows(PendingAnalysisException.class, () -> store.retain(1L, report(null)));
        store.release(claim);
        assertNotNull(store.retain(2L, report(null)));
        assertThrows(PendingAnalysisException.class, () -> store.claim(1L, id));
    }

    @Test void allowsRetryAfterReleaseButNeverAfterCompletion() {
        UUID id = store.retain(1L, report(null)).getPendingAnalysisId();
        var claim = store.claim(1L, id);
        assertThrows(PendingAnalysisException.class, () -> store.claim(1L, id));
        store.release(claim);
        claim = store.claim(1L, id);
        store.complete(claim);
        store.release(claim);
        assertThrows(PendingAnalysisException.class, () -> store.claim(1L, id));
    }

    @Test void allowsAnalysisOfLongNetworkMetadataButRejectsPersistenceBounds() {
        var report = report(null);
        report.setUrl("https://example.com/" + "x".repeat(300));
        report.getHttp().setServer("x".repeat(256));
        UUID id = store.retain(1L, report).getPendingAnalysisId();
        var claim = store.claim(1L, id);
        assertEquals(report.getUrl(), store.snapshot(claim).getUrl());
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, assertThrows(PendingAnalysisException.class,
                () -> store.validateForPersistence(store.snapshot(claim))).getStatus());
        store.release(claim);
        assertNotNull(store.claim(1L, id));
    }

    @Test void boundsSerializedBytesAndValidatesSettings() {
        var tiny = store(1, 1, 10);
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, assertThrows(PendingAnalysisException.class,
                () -> tiny.retain(1L, report(null))).getStatus());
        for (int[] settings : List.of(new int[]{0,1,1,1}, new int[]{1,0,1,1},new int[]{1,1,0,1},
                new int[]{1,2,1,1},new int[]{1,1,1,0})) {
            assertThrows(IllegalArgumentException.class, () -> new PendingAnalysisStore(settings[0],settings[1],settings[2],settings[3],clock,mapper,null));
        }
    }

    @Test void concurrentClaimsHaveExactlyOneWinner() throws Exception {
        UUID id = store.retain(1L, report(null)).getPendingAnalysisId();
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(8)) {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i=0;i<8;i++) results.add(executor.submit(() -> {
                start.await();
                try { store.claim(1L,id); return true; }
                catch (PendingAnalysisException expected) { assertEquals(HttpStatus.CONFLICT, expected.getStatus()); return false; }
            }));
            start.countDown();
            int winners=0;
            for (var result : results) if (result.get(5,TimeUnit.SECONDS)) winners++;
            assertEquals(1,winners);
        }
    }
}
