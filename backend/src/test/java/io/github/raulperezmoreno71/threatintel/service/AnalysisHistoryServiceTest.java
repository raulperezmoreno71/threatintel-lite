package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.dto.SaveAnalysisRequest;
import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisNotFoundException;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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

    @Test
    void shouldSaveCompleteHttpsAnalysis() {
        User authenticatedUser = new User(
                "test@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );
        SaveAnalysisRequest request = createSaveAnalysisRequest(
                new SslAnalysisResult(
                        "Let's Encrypt",
                        "example.com",
                        LocalDate.of(2026, 7, 1),
                        LocalDate.of(2026, 10, 1),
                        46,
                        SslStatus.GOOD,
                        null
                )
        );

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(authenticatedUser));

        analysisHistoryService.saveAnalysis(request);

        ArgumentCaptor<Analysis> analysisCaptor =
                ArgumentCaptor.forClass(Analysis.class);

        verify(analysisRepository).save(analysisCaptor.capture());

        Analysis savedAnalysis = analysisCaptor.getValue();

        assertEquals("URL analyzed successfully", savedAnalysis.getMessage());
        assertEquals("https://example.com", savedAnalysis.getUrl());
        assertEquals("example.com", savedAnalysis.getDomain());
        assertSame(authenticatedUser, savedAnalysis.getUser());
        assertTrue(authenticatedUser.getAnalyses().contains(savedAnalysis));

        assertEquals(
                List.of("93.184.216.34", "93.184.216.35"),
                savedAnalysis.getDnsAnalysis().getIps()
        );

        HttpAnalysis savedHttp = savedAnalysis.getHttpAnalysis();

        assertEquals(200, savedHttp.getStatusCode());
        assertEquals("text/html", savedHttp.getContentType());
        assertEquals("nginx", savedHttp.getServer());
        assertEquals(1500L, savedHttp.getContentLength());
        assertEquals("https://example.com", savedHttp.getFinalUrl());
        assertEquals(120L, savedHttp.getTotalResponseTimeMs());
        assertEquals(2, savedHttp.getRedirectChain().size());

        RedirectStepEntity firstRedirect = savedHttp.getRedirectChain().get(0);

        assertEquals("http://example.com", firstRedirect.getUrl());
        assertEquals(301, firstRedirect.getStatusCode());
        assertEquals("https://example.com", firstRedirect.getLocation());
        assertEquals(50L, firstRedirect.getResponseTimeMs());

        for (RedirectStepEntity redirect : savedHttp.getRedirectChain()) {
            assertSame(savedHttp, redirect.getHttpAnalysis());
        }

        SslAnalysis savedSsl = savedAnalysis.getSslAnalysis();

        assertNotNull(savedSsl);
        assertEquals("Let's Encrypt", savedSsl.getIssuer());
        assertEquals("example.com", savedSsl.getSubject());
        assertEquals(LocalDate.of(2026, 7, 1), savedSsl.getValidFrom());
        assertEquals(LocalDate.of(2026, 10, 1), savedSsl.getValidUntil());
        assertEquals(46L, savedSsl.getDaysUntilExpiration());
        assertEquals(SslStatus.GOOD, savedSsl.getStatus());
        assertNull(savedSsl.getRecommendation());

        SecurityHeadersAnalysis savedHeaders =
                savedAnalysis.getSecurityHeadersAnalysis();

        assertEquals(6, savedHeaders.getHeaders().size());
        assertEquals(
                List.of(
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "Referrer-Policy",
                        "Permissions-Policy"
                ),
                savedHeaders.getHeaders().stream()
                        .map(SecurityHeaderResultEntity::getHeaderName)
                        .toList()
        );

        for (SecurityHeaderResultEntity header : savedHeaders.getHeaders()) {
            assertTrue(header.isPresent());
            assertEquals(SecurityStatus.GOOD, header.getStatus());
            assertNull(header.getRecommendation());
            assertSame(savedHeaders, header.getSecurityHeadersAnalysis());
        }

        SecurityAssessmentEntity savedAssessment =
                savedAnalysis.getSecurityAssessmentAnalysis();

        assertEquals(100, savedAssessment.getScore());
        assertEquals("A", savedAssessment.getGrade());
        assertEquals(6, savedAssessment.getGoodHeaders());
        assertEquals(0, savedAssessment.getWarningHeaders());
        assertEquals(0, savedAssessment.getMissingHeaders());

        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    void shouldSaveHttpAnalysisWithoutSsl() {
        User authenticatedUser = new User(
                "test@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );
        SaveAnalysisRequest request = createSaveAnalysisRequest(null);

        request.setUrl("http://example.com");

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(authenticatedUser));

        analysisHistoryService.saveAnalysis(request);

        ArgumentCaptor<Analysis> analysisCaptor =
                ArgumentCaptor.forClass(Analysis.class);

        verify(analysisRepository).save(analysisCaptor.capture());

        Analysis savedAnalysis = analysisCaptor.getValue();

        assertEquals("http://example.com", savedAnalysis.getUrl());
        assertNull(savedAnalysis.getSslAnalysis());
        assertNotNull(savedAnalysis.getDnsAnalysis());
        assertNotNull(savedAnalysis.getHttpAnalysis());
        assertNotNull(savedAnalysis.getSecurityHeadersAnalysis());
        assertNotNull(savedAnalysis.getSecurityAssessmentAnalysis());
        assertSame(authenticatedUser, savedAnalysis.getUser());
        assertTrue(authenticatedUser.getAnalyses().contains(savedAnalysis));

        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    void shouldNotSaveAnalysisWhenAuthenticatedUserDoesNotExist() {
        SaveAnalysisRequest request = mock(SaveAnalysisRequest.class);

        when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.empty());

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> analysisHistoryService.saveAnalysis(request)
        );

        assertEquals("Authenticated user not found", exception.getMessage());

        verify(userRepository).findByEmail("test@example.com");
        verifyNoInteractions(request);
        verify(analysisRepository, never()).save(any(Analysis.class));
    }

    private SaveAnalysisRequest createSaveAnalysisRequest(SslAnalysisResult ssl) {
        DnsAnalysisResult dns = new DnsAnalysisResult(
                List.of("93.184.216.34", "93.184.216.35")
        );

        HttpAnalysisResult http = new HttpAnalysisResult(
                200,
                "text/html",
                "nginx",
                1500L,
                "https://example.com",
                120L,
                List.of(
                        new RedirectStep(
                                "http://example.com",
                                301,
                                "https://example.com",
                                50L
                        ),
                        new RedirectStep(
                                "https://example.com",
                                200,
                                null,
                                70L
                        )
                )
        );

        SecurityHeaderResult goodHeader = new SecurityHeaderResult(
                true,
                "valid-value",
                SecurityStatus.GOOD,
                null
        );

        SecurityHeadersAnalysisResult securityHeaders =
                new SecurityHeadersAnalysisResult(
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader
                );

        SecurityAssessmentResult securityAssessment =
                new SecurityAssessmentResult(
                        100,
                        "A",
                        6,
                        0,
                        0
                );

        return new SaveAnalysisRequest(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                dns,
                http,
                ssl,
                securityHeaders,
                securityAssessment
        );
    }
}
