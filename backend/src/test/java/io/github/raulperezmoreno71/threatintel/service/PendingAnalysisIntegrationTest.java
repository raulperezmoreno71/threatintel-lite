package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.*;
import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.exception.PendingAnalysisException;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.*;
import jakarta.servlet.http.Cookie;
import jakarta.validation.Validator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.*;
import org.springframework.transaction.support.*;
import org.testcontainers.junit.jupiter.*;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static io.github.raulperezmoreno71.threatintel.support.AnalysisFixtures.report;
import static io.github.raulperezmoreno71.threatintel.support.CsrfRequestPostProcessors.csrfCookieAndHeader;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@Import(PendingAnalysisIntegrationTest.DraftsConfig.class)
class PendingAnalysisIntegrationTest {
    @Container static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16")
            .withDatabaseName("pending_analysis_test").withUsername("test").withPassword("test");
    private static final Clock CLOCK = mock(Clock.class);
    private static final Instant START = Instant.parse("2026-01-01T12:00:00Z");

    @TestConfiguration static class DraftsConfig {
        @Bean @Primary PendingAnalysisStore testPendingStore(ObjectMapper mapper, Validator validator) {
            return new PendingAnalysisStore(900,5,500,131072,CLOCK,mapper,validator);
        }
    }
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("jwt.secret", () -> "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=");
    }
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired AnalysisRepository analyses;
    @Autowired PendingAnalysisStore drafts;
    @Autowired AnalysisHistoryService history;
    @Autowired JwtService jwt;
    @Autowired PlatformTransactionManager transactions;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean AnalyzeService analyzer;
    private User owner;
    private User other;

    @BeforeEach void setup() {
        when(CLOCK.instant()).thenReturn(START);
        owner=users.saveAndFlush(new User(UUID.randomUUID()+"@example.com","hash",UserStatus.ACTIVE));
        other=users.saveAndFlush(new User(UUID.randomUUID()+"@example.com","hash",UserStatus.ACTIVE));
        when(analyzer.analyze(any())).thenReturn(report(new SslAnalysisResult("Example CA","example.com",
                LocalDate.of(2025,1,1),LocalDate.of(2027,1,1),365,SslStatus.GOOD,null)));
    }
    @AfterEach void clearSecurity() { SecurityContextHolder.clearContext(); }
    private Cookie cookie(User user) { return new Cookie("access_token",jwt.generateToken(user)); }
    private void authenticate(User user) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user.getEmail(),null,List.of()));
    }
    private String analyze() throws Exception {
        String body=mvc.perform(post("/api/analyze").cookie(cookie(owner)).with(csrfCookieAndHeader())
                .contentType(MediaType.APPLICATION_JSON).content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.expiresAt").value(START.plusSeconds(900).toString()))
                .andReturn().getResponse().getContentAsString();
        return mapper.readTree(body).get("pendingAnalysisId").asString();
    }
    private org.springframework.test.web.servlet.ResultActions save(User user,String id) throws Exception {
        return mvc.perform(post("/api/analyses").cookie(cookie(user)).with(csrfCookieAndHeader())
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("pendingAnalysisId",id))));
    }

    @Test void savesServerSnapshotDespiteForgedContentAndKeepsHistoryOwned() throws Exception {
        String id=analyze();
        mvc.perform(post("/api/analyses").cookie(cookie(owner)).with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of(
                                "pendingAnalysisId",id,"url","https://forged.example","userId",other.getId(),
                                "securityAssessment",Map.of("score",0),"securityHeaders",Map.of("contentSecurityPolicy",Map.of("value","forged"))))))
                .andExpect(status().isCreated());
        var rows=analyses.findByUser(owner);
        assertEquals(1,rows.size());
        long storedId=rows.getFirst().getId();
        mvc.perform(get("/api/analyses/"+storedId).cookie(cookie(owner)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.url").value("https://example.com"))
                .andExpect(jsonPath("$.dns.ips.length()").value(2))
                .andExpect(jsonPath("$.http.redirectChain.length()").value(2))
                .andExpect(jsonPath("$.http.server").value("nginx"))
                .andExpect(jsonPath("$.ssl.issuer").value("Example CA"))
                .andExpect(jsonPath("$.securityAssessment.score").value(100))
                .andExpect(jsonPath("$.securityHeaders.contentSecurityPolicy.value").value("valid-value"))
                .andExpect(jsonPath("$.pendingAnalysisId").doesNotExist());
        mvc.perform(get("/api/analyses/"+storedId).cookie(cookie(other))).andExpect(status().isNotFound());
        mvc.perform(get("/api/analyses").cookie(cookie(other))).andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(delete("/api/analyses/"+storedId).cookie(cookie(other)).with(csrfCookieAndHeader())).andExpect(status().isNotFound());
        save(owner,id).andExpect(status().isNotFound());
        assertEquals(1,analyses.findByUser(owner).size());
        verify(analyzer,times(1)).analyze(any());
    }

    @Test void rejectsOtherOwnerUnknownAndExpiredIdsWithoutConsumingValidDraft() throws Exception {
        String id=analyze();
        save(other,id).andExpect(status().isNotFound()).andExpect(jsonPath("$.path").value("/api/analyses"));
        save(owner,UUID.randomUUID().toString()).andExpect(status().isNotFound());
        save(owner,id).andExpect(status().isCreated());
        String expiring=analyze();
        when(CLOCK.instant()).thenReturn(START.plusSeconds(900));
        save(owner,expiring).andExpect(status().isNotFound()).andExpect(jsonPath("$.message").value("Pending analysis unavailable or expired. Analyze the URL again."));
        assertEquals(1,analyses.findByUser(owner).size());
    }

    @Test void failedAnalysisCreatesNoDraftAndOldFullReportCannotBeSaved() throws Exception {
        when(analyzer.analyze(any())).thenThrow(new IllegalArgumentException("Invalid destination"));
        mvc.perform(post("/api/analyze").cookie(cookie(owner)).with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.pendingAnalysisId").doesNotExist());
        mvc.perform(post("/api/analyses").cookie(cookie(owner)).with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(report(null))))
                .andExpect(status().isBadRequest());
        assertTrue(analyses.findByUser(owner).isEmpty());
    }

    @Test void longReportRemainsViewableButCannotExceedPersistenceBounds() throws Exception {
        var large=report(null);
        large.setUrl("https://example.com/"+"x".repeat(300));
        large.getHttp().setServer("x".repeat(256));
        when(analyzer.analyze(any())).thenReturn(large);
        String id=analyze();
        save(owner,id).andExpect(status().isUnprocessableEntity()).andExpect(jsonPath("$.message").value(
                "The generated report exceeds supported storage bounds and cannot be saved. Analyze another URL."));
        save(owner,id).andExpect(status().isUnprocessableEntity());
        assertTrue(analyses.findByUser(owner).isEmpty());
        when(analyzer.analyze(any())).thenReturn(report(null));
        save(owner,analyze()).andExpect(status().isCreated());
    }

    @Test void concurrentSavePersistsOnceAndDoesNotHoldGlobalStoreLock() throws Exception {
        UUID id=drafts.retain(owner.getId(),report(null)).getPendingAnalysisId();
        var enteredCommit=new CountDownLatch(1);
        var allowCommit=new CountDownLatch(1);
        var slowHistory=new AnalysisHistoryService(analyses,users,drafts,beforeCommit(() -> {
            enteredCommit.countDown();
            try { assertTrue(allowCommit.await(10,TimeUnit.SECONDS)); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        }));
        try (var executor=Executors.newFixedThreadPool(2)) {
            var winner=executor.submit(() -> {
                authenticate(owner);
                try { slowHistory.saveAnalysis(new SaveAnalysisRequest(id)); }
                finally { SecurityContextHolder.clearContext(); }
            });
            try {
                assertTrue(enteredCommit.await(10,TimeUnit.SECONDS));
                assertNotNull(executor.submit(() -> drafts.retain(other.getId(),report(null))).get(3,TimeUnit.SECONDS));
                authenticate(owner);
                assertEquals(org.springframework.http.HttpStatus.CONFLICT, assertThrows(PendingAnalysisException.class,
                        () -> history.saveAnalysis(new SaveAnalysisRequest(id))).getStatus());
            } finally { allowCommit.countDown(); }
            winner.get(10,TimeUnit.SECONDS);
        }
        assertEquals(1,analyses.findByUser(owner).size());
        assertThrows(PendingAnalysisException.class, () -> history.saveAnalysis(new SaveAnalysisRequest(id)));
    }

    @Test void commitFailureRollsBackWholeGraphAndRetainsDraftForRetry() {
        UUID id=drafts.retain(owner.getId(),report(new SslAnalysisResult("CA","example.com",LocalDate.now(),LocalDate.now().plusDays(1),1,SslStatus.GOOD,null))).getPendingAnalysisId();
        Map<String,Long> before=graphCounts();
        var failingHistory=new AnalysisHistoryService(analyses,users,drafts,beforeCommit(() -> {
            throw new DataIntegrityViolationException("Simulated deferred commit failure");
        }));
        authenticate(owner);
        assertThrows(DataIntegrityViolationException.class, () -> failingHistory.saveAnalysis(new SaveAnalysisRequest(id)));
        assertEquals(before,graphCounts(),"All inserts must roll back, including cascaded children");
        history.saveAnalysis(new SaveAnalysisRequest(id));
        assertEquals(1,analyses.findByUser(owner).size());
        assertThrows(PendingAnalysisException.class, () -> history.saveAnalysis(new SaveAnalysisRequest(id)));
    }

    @Test void databaseConstraintFailureRollsBackChildrenAndAllowsRetry() {
        UUID id=drafts.retain(owner.getId(),report(null)).getPendingAnalysisId();
        Map<String,Long> before=graphCounts();
        // Delete the owner inside the save transaction: the real PostgreSQL FK rejects the graph.
        // Rolling back that transaction also restores the owner, allowing the identical draft to retry.
        PlatformTransactionManager invalidOwner = new PlatformTransactionManager() {
            public TransactionStatus getTransaction(TransactionDefinition definition) {
                TransactionStatus status=transactions.getTransaction(definition);
                users.deleteById(owner.getId());
                users.flush();
                return status;
            }
            public void commit(TransactionStatus status) { transactions.commit(status); }
            public void rollback(TransactionStatus status) { transactions.rollback(status); }
        };
        authenticate(owner);
        var failingHistory=new AnalysisHistoryService(analyses,users,drafts,invalidOwner);
        assertThrows(DataIntegrityViolationException.class, () -> failingHistory.saveAnalysis(new SaveAnalysisRequest(id)));
        assertEquals(before,graphCounts());
        assertTrue(users.findById(owner.getId()).isPresent());
        history.saveAnalysis(new SaveAnalysisRequest(id));
        assertEquals(1,analyses.findByUser(owner).size());
    }

    @Test void errorReportedAfterRealCommitCannotPersistTheSameIdentifierTwice() {
        UUID id=drafts.retain(owner.getId(),report(null)).getPendingAnalysisId();
        PlatformTransactionManager lostResponse = new PlatformTransactionManager() {
            public TransactionStatus getTransaction(TransactionDefinition definition) {
                return transactions.getTransaction(definition);
            }
            public void commit(TransactionStatus status) {
                transactions.commit(status);
                throw new TransactionSystemException("Simulated connection failure after commit");
            }
            public void rollback(TransactionStatus status) { transactions.rollback(status); }
        };
        authenticate(owner);
        var uncertainHistory=new AnalysisHistoryService(analyses,users,drafts,lostResponse);
        assertThrows(TransactionSystemException.class, () -> uncertainHistory.saveAnalysis(new SaveAnalysisRequest(id)));
        assertEquals(1,analyses.findByUser(owner).size());
        assertThrows(PendingAnalysisException.class, () -> history.saveAnalysis(new SaveAnalysisRequest(id)));
        assertEquals(1,analyses.findByUser(owner).size());
    }

    private PlatformTransactionManager beforeCommit(Runnable action) {
        return new PlatformTransactionManager() {
            public TransactionStatus getTransaction(TransactionDefinition definition) {
                TransactionStatus status=transactions.getTransaction(definition);
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override public void beforeCommit(boolean readOnly) { action.run(); }
                });
                return status;
            }
            public void commit(TransactionStatus status) { transactions.commit(status); }
            public void rollback(TransactionStatus status) { transactions.rollback(status); }
        };
    }
    private Map<String,Long> graphCounts() {
        Map<String,Long> counts=new HashMap<>();
        for (String table:List.of("analysis","dns_analysis","http_analysis","redirect_step_entity","ssl_analysis",
                "security_headers_analysis","security_header_result_entity","security_assessment_entity")) {
            counts.put(table,jdbc.queryForObject("select count(*) from "+table,Long.class));
        }
        return counts;
    }
}
