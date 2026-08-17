package io.github.raulperezmoreno71.threatintel.repository;

import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Testcontainers
@AutoConfigureTestDatabase(
        replace = AutoConfigureTestDatabase.Replace.NONE
)
class AnalysisRepositoryIntegrationTest {

    @Container
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16")
            .withDatabaseName("threatintel_test")
            .withUsername("test")
            .withPassword("test");

    @Autowired
    private AnalysisRepository analysisRepository;

    @Autowired
    private EntityManager entityManager;

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Test
    void shouldSaveAndFindAnalysisById() {
        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                null,
                null,
                null,
                null,
                null
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        assertNotNull(saved.getId());

        Optional<Analysis> found = analysisRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertEquals("https://example.com", found.get().getUrl());
        assertEquals("example.com", found.get().getDomain());
    }

    @Test
    void shouldPersistDnsAnalysisWithIps() {
        DnsAnalysis dnsAnalysis = new DnsAnalysis(List.of("93.184.216.34", "93.184.216.35"));

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                dnsAnalysis,
                null,
                null,
                null,
                null
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        Optional<Analysis> found = analysisRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertNotNull(found.get().getId());
        assertEquals(2, found.get().getDnsAnalysis().getIps().size());
        assertTrue(found.get().getDnsAnalysis().getIps().contains("93.184.216.34"));
        assertTrue(found.get().getDnsAnalysis().getIps().contains("93.184.216.35"));
    }

    @Test
    void shouldPersistHttpAnalysisWithRedirectChain() {
        HttpAnalysis httpAnalysis = new HttpAnalysis(
                200,
                "text/html",
                "nginx",
                2048L,
                "https://example.com",
                180L
        );

        RedirectStepEntity redirectStep = new RedirectStepEntity(
                "http://example.com",
                301,
                "https://example.com",
                45L,
                httpAnalysis
        );

        httpAnalysis.setRedirectChain(List.of(redirectStep));

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                null,
                httpAnalysis,
                null,
                null,
                null
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        Optional<Analysis> found = analysisRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertNotNull(found.get().getHttpAnalysis());
        assertEquals(200, found.get().getHttpAnalysis().getStatusCode());
        assertEquals(1, found.get().getHttpAnalysis().getRedirectChain().size());
        assertEquals("http://example.com", found.get().getHttpAnalysis().getRedirectChain().get(0).getUrl());
        assertEquals(301, found.get().getHttpAnalysis().getRedirectChain().get(0).getStatusCode());
        assertEquals("https://example.com", found.get().getHttpAnalysis().getRedirectChain().get(0).getLocation());
    }

    @Test
    void shouldPersistSslAnalysis() {
        SslAnalysis sslAnalysis = new SslAnalysis(
                "Let's Encrypt",
                "example.com",
                LocalDate.of(2026, 7, 1),
                LocalDate.of(2026, 10, 1),
                45L,
                SslStatus.GOOD,
                null
        );

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                null,
                null,
                sslAnalysis,
                null,
                null
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        Optional<Analysis> found = analysisRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertNotNull(found.get().getSslAnalysis());
        assertEquals("Let's Encrypt", found.get().getSslAnalysis().getIssuer());
        assertEquals("example.com", found.get().getSslAnalysis().getSubject());
        assertEquals(LocalDate.of(2026, 7, 1), found.get().getSslAnalysis().getValidFrom());
        assertEquals(LocalDate.of(2026, 10, 1), found.get().getSslAnalysis().getValidUntil());
        assertEquals(45L, found.get().getSslAnalysis().getDaysUntilExpiration());
        assertEquals(SslStatus.GOOD, found.get().getSslAnalysis().getStatus());
    }

    @Test
    void shouldPersistSecurityHeadersAnalysis() {
        SecurityHeaderResultEntity securityHeaderResultEntity = new SecurityHeaderResultEntity(
                "Strict-Transport-Security",
                true,
                "max-age=31536000; includeSubDomains",
                SecurityStatus.GOOD,
                null
        );

        SecurityHeadersAnalysis securityHeadersAnalysis = new SecurityHeadersAnalysis(List.of(securityHeaderResultEntity));

        securityHeaderResultEntity.setSecurityHeadersAnalysis(securityHeadersAnalysis);

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                null,
                null,
                null,
                securityHeadersAnalysis,
                null
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        Optional<Analysis> found = analysisRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertNotNull(found.get().getSecurityHeadersAnalysis());
        assertEquals(1, found.get().getSecurityHeadersAnalysis().getHeaders().size());
        assertEquals("Strict-Transport-Security", found.get().getSecurityHeadersAnalysis().getHeaders().get(0).getHeaderName());
        assertTrue(found.get().getSecurityHeadersAnalysis().getHeaders().get(0).isPresent());
        assertEquals("max-age=31536000; includeSubDomains", found.get().getSecurityHeadersAnalysis().getHeaders().get(0).getValue());
        assertEquals(SecurityStatus.GOOD, found.get().getSecurityHeadersAnalysis().getHeaders().get(0).getStatus());
    }

    @Test
    void shouldPersistSecurityAssessment() {
        SecurityAssessmentEntity securityAssessmentEntity = new SecurityAssessmentEntity(
                85,
                "A",
                5,
                1,
                0
        );

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                null,
                null,
                null,
                null,
                securityAssessmentEntity
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        Optional<Analysis> found = analysisRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertNotNull(found.get().getSecurityAssessmentAnalysis());
        assertEquals(85, found.get().getSecurityAssessmentAnalysis().getScore());
        assertEquals("A", found.get().getSecurityAssessmentAnalysis().getGrade());
        assertEquals(5, found.get().getSecurityAssessmentAnalysis().getGoodHeaders());
        assertEquals(1, found.get().getSecurityAssessmentAnalysis().getWarningHeaders());
        assertEquals(0, found.get().getSecurityAssessmentAnalysis().getMissingHeaders());
    }

    @Test
    void shouldDeleteAnalysis() {
        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                null,
                null,
                null,
                null,
                null
        );

        Analysis saves = analysisRepository.saveAndFlush(analysis);

        Long id = saves.getId();

        analysisRepository.delete(saves);
        analysisRepository.flush();

        Optional<Analysis> found = analysisRepository.findById(id);

        assertTrue(found.isEmpty());
    }

    @Test
    void shouldDeleteRelatedEntitiesByCascade() {
        DnsAnalysis dnsAnalysis = new DnsAnalysis(List.of());
        HttpAnalysis httpAnalysis = new HttpAnalysis();
        RedirectStepEntity redirectStepEntity = new RedirectStepEntity(
                "http://example.com",
                301,
                "https://example.com",
                45L,
                httpAnalysis
        );
        httpAnalysis.setRedirectChain(List.of(redirectStepEntity));
        SslAnalysis sslAnalysis = new SslAnalysis();
        SecurityHeaderResultEntity securityHeaderResultEntity = new SecurityHeaderResultEntity(
                "Strict-Transport-Security",
                true,
                "max-age=31536000",
                SecurityStatus.GOOD,
                null
        );
        SecurityHeadersAnalysis securityHeadersAnalysis = new SecurityHeadersAnalysis(List.of(securityHeaderResultEntity));
        securityHeaderResultEntity.setSecurityHeadersAnalysis(securityHeadersAnalysis);
        SecurityAssessmentEntity securityAssessmentEntity = new SecurityAssessmentEntity();

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                LocalDateTime.of(2026, 8, 17, 13, 0),
                dnsAnalysis,
                httpAnalysis,
                sslAnalysis,
                securityHeadersAnalysis,
                securityAssessmentEntity
        );

        Analysis saved = analysisRepository.saveAndFlush(analysis);

        Long analysisId = saved.getId();
        Long dnsId = saved.getDnsAnalysis().getId();
        Long httpId = saved.getHttpAnalysis().getId();
        Long redirectId = saved.getHttpAnalysis().getRedirectChain().get(0).getId();
        Long sslId = saved.getSslAnalysis().getId();
        Long headerId = saved.getSecurityHeadersAnalysis().getHeaders().get(0).getId();
        Long headersId = saved.getSecurityHeadersAnalysis().getId();
        Long assessmentId = saved.getSecurityAssessmentAnalysis().getId();

        analysisRepository.delete(saved);
        analysisRepository.flush();

        entityManager.clear();

        Analysis deletedAnalysis = entityManager.find(Analysis.class, analysisId);
        DnsAnalysis deletedDns = entityManager.find(DnsAnalysis.class, dnsId);
        HttpAnalysis deletedHttp = entityManager.find(HttpAnalysis.class, httpId);
        RedirectStepEntity deletedRedirect = entityManager.find(RedirectStepEntity.class, redirectId);
        SslAnalysis deletedSsl = entityManager.find(SslAnalysis.class, sslId);
        SecurityHeaderResultEntity deletedHeader = entityManager.find(SecurityHeaderResultEntity.class, headerId);
        SecurityHeadersAnalysis deletedHeaders = entityManager.find(SecurityHeadersAnalysis.class, headersId);
        SecurityAssessmentEntity deletedAssessment = entityManager.find(SecurityAssessmentEntity.class, assessmentId);

        assertNull(deletedAnalysis);
        assertNull(deletedDns);
        assertNull(deletedHttp);
        assertNull(deletedRedirect);
        assertNull(deletedSsl);
        assertNull(deletedHeader);
        assertNull(deletedHeaders);
        assertNull(deletedAssessment);
    }
}
