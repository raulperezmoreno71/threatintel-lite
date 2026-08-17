package io.github.raulperezmoreno71.threatintel.repository;

import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import io.github.raulperezmoreno71.threatintel.entity.DnsAnalysis;
import io.github.raulperezmoreno71.threatintel.entity.HttpAnalysis;
import io.github.raulperezmoreno71.threatintel.entity.RedirectStepEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

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
}
