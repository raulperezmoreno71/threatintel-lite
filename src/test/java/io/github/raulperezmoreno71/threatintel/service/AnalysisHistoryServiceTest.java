package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisNotFoundException;
import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AnalysisHistoryServiceTest {

    private AnalysisRepository analysisRepository;
    private AnalysisHistoryService analysisHistoryService;
    private UserRepository userRepository;
    private User user;

    @BeforeEach
    void setUp() {
        analysisRepository = mock(AnalysisRepository.class);
        userRepository = mock(UserRepository.class);
        user = mock(User.class);

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "test@example.com",
                        null,
                        Collections.emptyList()
                )
        );

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(user));

        analysisHistoryService = new AnalysisHistoryService(
                analysisRepository,
                userRepository
        );
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldReturnAnalysisById() {
        Analysis analysis = mock(Analysis.class);

        when(analysis.getId()).thenReturn(1L);
        when(analysis.getMessage()).thenReturn("URL analyzed successfully");
        when(analysis.getUrl()).thenReturn("https://example.com");
        when(analysis.getDomain()).thenReturn("example.com");

        when(analysisRepository.findByIdAndUser(1L, user))
                .thenReturn(Optional.of(analysis));

        AnalysisHistoryResponse response =
                analysisHistoryService.getAnalysisById(1L);

        assertEquals(1L, response.getId());
        assertEquals("https://example.com", response.getUrl());
        assertEquals("example.com", response.getDomain());
        assertEquals("URL analyzed successfully", response.getMessage());

        verify(analysisRepository).findByIdAndUser(1L, user);
    }

    @Test
    void shouldThrowExceptionWhenAnalysisDoesNotExist() {
        when(analysisRepository.findByIdAndUser(99L, user))
                .thenReturn(Optional.empty());

        AnalysisNotFoundException exception = assertThrows(
                AnalysisNotFoundException.class,
                () -> analysisHistoryService.getAnalysisById(99L)
        );

        assertEquals(
                "Analysis not found with id: 99",
                exception.getMessage()
        );

        verify(analysisRepository).findByIdAndUser(99L, user);
    }

    @Test
    void shouldReturnAllAnalysis() {
        Analysis analysis1 = mock(Analysis.class);
        Analysis analysis2 = mock(Analysis.class);

        when(analysis1.getId()).thenReturn(1L);
        when(analysis1.getDomain()).thenReturn("example.com");
        when(analysis1.getUrl()).thenReturn("https://example.com");

        when(analysis2.getId()).thenReturn(2L);
        when(analysis2.getDomain()).thenReturn("google.com");
        when(analysis2.getUrl()).thenReturn("https://google.com");

        when(analysisRepository.findByUser(user))
                .thenReturn(List.of(analysis1, analysis2));

        List<AnalysisHistoryResponse> responses =
                analysisHistoryService.getAllAnalyses();

        assertEquals(2, responses.size());

        assertEquals(1L, responses.get(0).getId());
        assertEquals(
                "https://example.com",
                responses.get(0).getUrl()
        );
        assertEquals(
                "example.com",
                responses.get(0).getDomain()
        );

        assertEquals(2L, responses.get(1).getId());
        assertEquals(
                "https://google.com",
                responses.get(1).getUrl()
        );
        assertEquals(
                "google.com",
                responses.get(1).getDomain()
        );

        verify(analysisRepository).findByUser(user);
    }

    @Test
    void shouldReturnEmptyListWhenThereAreNoAnalyses() {
        when(analysisRepository.findByUser(user))
                .thenReturn(List.of());

        List<AnalysisHistoryResponse> responses =
                analysisHistoryService.getAllAnalyses();

        assertTrue(responses.isEmpty());

        verify(analysisRepository).findByUser(user);
    }

    @Test
    void shouldDeleteAnalysisById() {
        Analysis analysis = mock(Analysis.class);

        when(analysisRepository.findByIdAndUser(1L, user))
                .thenReturn(Optional.of(analysis));

        analysisHistoryService.deleteAnalysisById(1L);

        verify(analysisRepository).findByIdAndUser(1L, user);
        verify(analysisRepository).delete(analysis);
    }

    @Test
    void shouldThrowExceptionWhenAnalysisToDeleteDoesNotExist() {
        when(analysisRepository.findByIdAndUser(99L, user))
                .thenReturn(Optional.empty());

        AnalysisNotFoundException exception = assertThrows(
                AnalysisNotFoundException.class,
                () -> analysisHistoryService.deleteAnalysisById(99L)
        );

        assertEquals(
                "Analysis not found with id: 99",
                exception.getMessage()
        );

        verify(analysisRepository).findByIdAndUser(99L, user);
        verify(analysisRepository, never()).delete(any());
    }

    @Test
    void shouldMapAllAnalysisPartsCorrectly() {
        DnsAnalysis dnsAnalysis = mock(DnsAnalysis.class);
        HttpAnalysis httpAnalysis = mock(HttpAnalysis.class);
        RedirectStepEntity redirectStepEntity =
                mock(RedirectStepEntity.class);
        SslAnalysis sslAnalysis = mock(SslAnalysis.class);
        SecurityHeadersAnalysis securityHeadersAnalysis =
                mock(SecurityHeadersAnalysis.class);
        SecurityHeaderResultEntity securityHeaderResultEntity =
                mock(SecurityHeaderResultEntity.class);
        SecurityAssessmentEntity securityAssessmentEntity =
                mock(SecurityAssessmentEntity.class);
        Analysis analysis = mock(Analysis.class);

        when(analysis.getId()).thenReturn(1L);
        when(analysis.getMessage())
                .thenReturn("URL analyzed successfully");
        when(analysis.getUrl())
                .thenReturn("https://example.com");
        when(analysis.getDomain())
                .thenReturn("example.com");
        when(analysis.getCreatedAt())
                .thenReturn(
                        LocalDateTime.of(
                                2026,
                                8,
                                16,
                                12,
                                0
                        )
                );

        when(analysis.getDnsAnalysis())
                .thenReturn(dnsAnalysis);
        when(dnsAnalysis.getIps())
                .thenReturn(List.of("93.184.216.34"));

        when(analysis.getHttpAnalysis())
                .thenReturn(httpAnalysis);
        when(httpAnalysis.getRedirectChain())
                .thenReturn(List.of(redirectStepEntity));

        when(redirectStepEntity.getUrl())
                .thenReturn("http://example.com");
        when(redirectStepEntity.getStatusCode())
                .thenReturn(301);
        when(redirectStepEntity.getLocation())
                .thenReturn("https://example.com");
        when(redirectStepEntity.getResponseTimeMs())
                .thenReturn(50L);

        when(httpAnalysis.getStatusCode())
                .thenReturn(200);
        when(httpAnalysis.getContentType())
                .thenReturn("text/html");
        when(httpAnalysis.getServer())
                .thenReturn("nginx");
        when(httpAnalysis.getContentLength())
                .thenReturn(1500L);
        when(httpAnalysis.getFinalUrl())
                .thenReturn("https://example.com");
        when(httpAnalysis.getTotalResponseTimeMs())
                .thenReturn(120L);

        when(analysis.getSslAnalysis())
                .thenReturn(sslAnalysis);
        when(sslAnalysis.getIssuer())
                .thenReturn("Let's Encrypt");
        when(sslAnalysis.getSubject())
                .thenReturn("example.com");
        when(sslAnalysis.getValidFrom())
                .thenReturn(LocalDate.of(2026, 7, 1));
        when(sslAnalysis.getValidUntil())
                .thenReturn(LocalDate.of(2026, 10, 1));
        when(sslAnalysis.getDaysUntilExpiration())
                .thenReturn(46L);
        when(sslAnalysis.getStatus())
                .thenReturn(SslStatus.GOOD);

        when(analysis.getSecurityHeadersAnalysis())
                .thenReturn(securityHeadersAnalysis);

        when(securityHeadersAnalysis.getHeaders())
                .thenReturn(List.of(securityHeaderResultEntity));

        when(securityHeaderResultEntity.getHeaderName())
                .thenReturn("Strict-Transport-Security");
        when(securityHeaderResultEntity.isPresent())
                .thenReturn(true);
        when(securityHeaderResultEntity.getValue())
                .thenReturn("max-age=31536000");
        when(securityHeaderResultEntity.getStatus())
                .thenReturn(SecurityStatus.GOOD);

        when(analysis.getSecurityAssessmentAnalysis())
                .thenReturn(securityAssessmentEntity);

        when(securityAssessmentEntity.getScore())
                .thenReturn(85);
        when(securityAssessmentEntity.getGrade())
                .thenReturn("A");
        when(securityAssessmentEntity.getGoodHeaders())
                .thenReturn(5);
        when(securityAssessmentEntity.getWarningHeaders())
                .thenReturn(1);
        when(securityAssessmentEntity.getMissingHeaders())
                .thenReturn(0);

        when(analysisRepository.findByIdAndUser(1L, user))
                .thenReturn(Optional.of(analysis));

        AnalysisHistoryResponse response =
                analysisHistoryService.getAnalysisById(1L);

        assertEquals(1L, response.getId());
        assertEquals(
                "https://example.com",
                response.getUrl()
        );
        assertEquals(
                "example.com",
                response.getDomain()
        );
        assertEquals(
                "URL analyzed successfully",
                response.getMessage()
        );

        assertEquals(
                LocalDateTime.of(2026, 8, 16, 12, 0),
                response.getCreatedAt()
        );

        assertEquals(
                "93.184.216.34",
                response.getDns().getIps().get(0)
        );

        assertEquals(
                200,
                response.getHttp().getStatusCode()
        );

        assertEquals(
                301,
                response.getHttp()
                        .getRedirectChain()
                        .get(0)
                        .getStatusCode()
        );

        assertEquals(
                "Let's Encrypt",
                response.getSsl().getIssuer()
        );

        assertTrue(
                response.getSecurityHeaders()
                        .getStrictTransportSecurity()
                        .isPresent()
        );

        assertEquals(
                85,
                response.getSecurityAssessment().getScore()
        );

        verify(analysisRepository)
                .findByIdAndUser(1L, user);
    }
}