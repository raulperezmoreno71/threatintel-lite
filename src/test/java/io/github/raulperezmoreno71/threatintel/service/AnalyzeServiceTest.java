package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.*;

class AnalyzeServiceTest {

    private UrlValidator urlValidator;
    private SslAnalyzer sslAnalyzer;
    private SecurityHeadersAnalyzer securityHeadersAnalyzer;
    private SecurityAssessmentCalculator securityAssessmentCalculator;
    private HttpAnalyzer httpAnalyzer;
    private DnsAnalyzer dnsAnalyzer;
    private AnalysisRepository analysisRepository;
    private UserRepository userRepository;
    private User user;

    private AnalyzeService analyzeService;

    @BeforeEach
    void setUp() {
        urlValidator = mock(UrlValidator.class);
        sslAnalyzer = mock(SslAnalyzer.class);
        securityHeadersAnalyzer = mock(SecurityHeadersAnalyzer.class);
        securityAssessmentCalculator = mock(SecurityAssessmentCalculator.class);
        httpAnalyzer = mock(HttpAnalyzer.class);
        dnsAnalyzer = mock(DnsAnalyzer.class);
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

        analyzeService = new AnalyzeService(
                urlValidator,
                dnsAnalyzer,
                httpAnalyzer,
                sslAnalyzer,
                securityHeadersAnalyzer,
                securityAssessmentCalculator,
                analysisRepository,
                userRepository
        );
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldOrchestrateCompleteUrlAnalysisCorrectly() {
        DnsAnalysisResult dnsAnalysisResult = mock(DnsAnalysisResult.class);
        HttpRedirectResult httpRedirectResult = mock(HttpRedirectResult.class);
        HttpAnalysisResult httpAnalysisResult = mock(HttpAnalysisResult.class);
        SslAnalysisResult sslAnalysisResult = mock(SslAnalysisResult.class);
        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = mock(SecurityHeadersAnalysisResult.class);
        SecurityAssessmentResult securityAssessmentResult = mock(SecurityAssessmentResult.class);
        HttpResponse<String> finalResponse = mock(HttpResponse.class);
        SecurityHeaderResult securityHeaderResult = mock(SecurityHeaderResult.class);

        when(dnsAnalyzer.analyze("example.com")).thenReturn(dnsAnalysisResult);
        when(httpAnalyzer.followRedirects("https://example.com")).thenReturn(httpRedirectResult);
        when(httpAnalyzer.analyzeResponse(httpRedirectResult)).thenReturn(httpAnalysisResult);
        when(httpAnalysisResult.getFinalUrl()).thenReturn("https://www.example.com/home");
        when(httpRedirectResult.getFinalResponse()).thenReturn(finalResponse);
        when(sslAnalyzer.analyze(
                "https://www.example.com/home",
                "www.example.com"
            )
        ).thenReturn(sslAnalysisResult);
        when(securityHeadersAnalyzer.analyze(finalResponse)).thenReturn(securityHeadersAnalysisResult);
        when(securityAssessmentCalculator.calculate(securityHeadersAnalysisResult)).thenReturn(securityAssessmentResult);
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        when(securityHeadersAnalysisResult.getContentSecurityPolicy()).thenReturn(securityHeaderResult);
        when(securityHeadersAnalysisResult.getPermissionsPolicy()).thenReturn(securityHeaderResult);
        when(securityHeadersAnalysisResult.getReferrerPolicy()).thenReturn(securityHeaderResult);
        when(securityHeadersAnalysisResult.getStrictTransportSecurity()).thenReturn(securityHeaderResult);
        when(securityHeadersAnalysisResult.getXContentTypeOptions()).thenReturn(securityHeaderResult);
        when(securityHeadersAnalysisResult.getXFrameOptions()).thenReturn(securityHeaderResult);

        AnalyzeRequest request = new AnalyzeRequest("https://example.com");

        AnalyzeResponse response = analyzeService.analyze(request);

        assertEquals("URL analyzed successfully", response.getMessage());
        assertEquals("https://example.com", response.getUrl());
        assertEquals("example.com", response.getDomain());
        assertSame(dnsAnalysisResult, response.getDns());
        assertSame(httpAnalysisResult, response.getHttp());
        assertSame(sslAnalysisResult, response.getSsl());
        assertSame(securityHeadersAnalysisResult, response.getSecurityHeaders());
        assertSame(securityAssessmentResult, response.getSecurityAssessment());

        verify(urlValidator).validate("https://example.com");
        verify(dnsAnalyzer).analyze("example.com");
        verify(httpAnalyzer).followRedirects("https://example.com");
        verify(httpAnalyzer).analyzeResponse(httpRedirectResult);
        verify(sslAnalyzer).analyze(
                "https://www.example.com/home",
                "www.example.com"
        );
        verify(securityHeadersAnalyzer).analyze(finalResponse);
        verify(securityAssessmentCalculator).calculate(securityHeadersAnalysisResult);

        verifyNoMoreInteractions(
                urlValidator,
                dnsAnalyzer,
                httpAnalyzer,
                sslAnalyzer,
                securityHeadersAnalyzer,
                securityAssessmentCalculator
        );
        verify(analysisRepository).save(any(Analysis.class));
    }
}
