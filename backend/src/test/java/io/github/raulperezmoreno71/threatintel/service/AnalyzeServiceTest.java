package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class AnalyzeServiceTest {

    private UrlValidator urlValidator;
    private SslAnalyzer sslAnalyzer;
    private SecurityHeadersAnalyzer securityHeadersAnalyzer;
    private SecurityAssessmentCalculator securityAssessmentCalculator;
    private HttpAnalyzer httpAnalyzer;
    private DnsAnalyzer dnsAnalyzer;

    private AnalyzeService analyzeService;

    @BeforeEach
    void setUp() {
        urlValidator = mock(UrlValidator.class);
        sslAnalyzer = mock(SslAnalyzer.class);
        securityHeadersAnalyzer = mock(SecurityHeadersAnalyzer.class);
        securityAssessmentCalculator = mock(SecurityAssessmentCalculator.class);
        httpAnalyzer = mock(HttpAnalyzer.class);
        dnsAnalyzer = mock(DnsAnalyzer.class);

        analyzeService = new AnalyzeService(
                urlValidator,
                dnsAnalyzer,
                httpAnalyzer,
                sslAnalyzer,
                securityHeadersAnalyzer,
                securityAssessmentCalculator
        );
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

        when(dnsAnalyzer.analyze(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(dnsAnalysisResult);
        when(httpAnalyzer.followRedirects(eq("https://example.com"), any(AnalysisDeadline.class))).thenReturn(httpRedirectResult);
        when(httpAnalyzer.analyzeResponse(httpRedirectResult)).thenReturn(httpAnalysisResult);
        when(httpAnalysisResult.getFinalUrl()).thenReturn("https://www.example.com/home");
        when(httpRedirectResult.getFinalResponse()).thenReturn(finalResponse);
        when(sslAnalyzer.analyze(eq("https://www.example.com/home"), eq("www.example.com"), any(AnalysisDeadline.class))
        ).thenReturn(sslAnalysisResult);
        when(securityHeadersAnalyzer.analyze(finalResponse)).thenReturn(securityHeadersAnalysisResult);
        when(securityAssessmentCalculator.calculate(securityHeadersAnalysisResult)).thenReturn(securityAssessmentResult);

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

        ArgumentCaptor<AnalysisDeadline> capturedDeadline = ArgumentCaptor.forClass(AnalysisDeadline.class);
        verify(urlValidator).validate(eq("https://example.com"), capturedDeadline.capture());
        AnalysisDeadline shared = capturedDeadline.getValue();
        verify(dnsAnalyzer).analyze(eq("example.com"), same(shared));
        verify(httpAnalyzer).followRedirects(eq("https://example.com"), same(shared));
        verify(httpAnalyzer).analyzeResponse(httpRedirectResult);
        verify(sslAnalyzer).analyze(eq("https://www.example.com/home"), eq("www.example.com"), same(shared));
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
    }

    @Test
    void shouldNotStartHttpAfterDnsExhaustsTheSharedBudget() {
        AtomicLong ticker = new AtomicLong();
        AnalysisDeadline deadline = new AnalysisDeadline(Duration.ofSeconds(15), ticker::get);
        when(dnsAnalyzer.analyze(eq("example.com"), same(deadline))).thenAnswer(invocation -> {
            ticker.set(Duration.ofSeconds(15).toNanos());
            return mock(DnsAnalysisResult.class);
        });

        assertThrows(AnalysisTimeoutException.class,
                () -> analyzeService.analyze(new AnalyzeRequest("https://example.com"), deadline));

        verifyNoInteractions(httpAnalyzer, sslAnalyzer, securityHeadersAnalyzer, securityAssessmentCalculator);
    }

    @Test
    void shouldRejectInvalidConfiguredTimeout() {
        assertThrows(IllegalArgumentException.class, () -> new AnalyzeService(urlValidator, dnsAnalyzer, httpAnalyzer,
                sslAnalyzer, securityHeadersAnalyzer, securityAssessmentCalculator, 0));
    }

    @Test
    void shouldStopAnalysisWhenUrlValidationFails() {
        AnalyzeRequest request = new AnalyzeRequest("invalid-url");
        IllegalArgumentException failure = new IllegalArgumentException("Invalid URL");
        doThrow(failure).when(urlValidator).validate(eq("invalid-url"), any(AnalysisDeadline.class));

        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> analyzeService.analyze(request)
        );

        assertSame(failure, thrown);
        verify(urlValidator).validate(eq("invalid-url"), any(AnalysisDeadline.class));
        verifyNoInteractions(
                dnsAnalyzer,
                httpAnalyzer,
                sslAnalyzer,
                securityHeadersAnalyzer,
                securityAssessmentCalculator
        );
    }

    @Test
    void shouldStopAnalysisWhenDnsAnalysisFails() {
        AnalyzeRequest request = new AnalyzeRequest("https://example.com");
        RuntimeException failure = new RuntimeException("DNS analysis failed");
        when(dnsAnalyzer.analyze(eq("example.com"), any(AnalysisDeadline.class))).thenThrow(failure);

        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> analyzeService.analyze(request)
        );

        assertSame(failure, thrown);
        verify(urlValidator).validate(eq("https://example.com"), any(AnalysisDeadline.class));
        verify(dnsAnalyzer).analyze(eq("example.com"), any(AnalysisDeadline.class));
        verifyNoInteractions(
                httpAnalyzer,
                sslAnalyzer,
                securityHeadersAnalyzer,
                securityAssessmentCalculator
        );
    }

    @Test
    void shouldStopAnalysisWhenHttpRequestFails() {
        AnalyzeRequest request = new AnalyzeRequest("https://example.com");
        DnsAnalysisResult dnsAnalysisResult = mock(DnsAnalysisResult.class);
        RuntimeException failure = new RuntimeException("HTTP analysis failed");
        when(dnsAnalyzer.analyze(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(dnsAnalysisResult);
        when(httpAnalyzer.followRedirects(eq("https://example.com"), any(AnalysisDeadline.class))).thenThrow(failure);

        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> analyzeService.analyze(request)
        );

        assertSame(failure, thrown);
        verify(urlValidator).validate(eq("https://example.com"), any(AnalysisDeadline.class));
        verify(dnsAnalyzer).analyze(eq("example.com"), any(AnalysisDeadline.class));
        verify(httpAnalyzer).followRedirects(eq("https://example.com"), any(AnalysisDeadline.class));
        verifyNoMoreInteractions(httpAnalyzer);
        verifyNoInteractions(
                sslAnalyzer,
                securityHeadersAnalyzer,
                securityAssessmentCalculator
        );
    }

    @Test
    void shouldStopAnalysisWhenSslAnalysisFails() {
        AnalyzeRequest request = new AnalyzeRequest("https://example.com");
        DnsAnalysisResult dnsAnalysisResult = mock(DnsAnalysisResult.class);
        HttpRedirectResult redirectResult = mock(HttpRedirectResult.class);
        HttpAnalysisResult httpAnalysisResult = mock(HttpAnalysisResult.class);
        RuntimeException failure = new RuntimeException("SSL analysis failed");

        when(dnsAnalyzer.analyze(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(dnsAnalysisResult);
        when(httpAnalyzer.followRedirects(eq("https://example.com"), any(AnalysisDeadline.class))).thenReturn(redirectResult);
        when(httpAnalyzer.analyzeResponse(redirectResult)).thenReturn(httpAnalysisResult);
        when(httpAnalysisResult.getFinalUrl()).thenReturn("https://www.example.com/home");
        when(sslAnalyzer.analyze(eq("https://www.example.com/home"), eq("www.example.com"), any(AnalysisDeadline.class)))
                .thenThrow(failure);

        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> analyzeService.analyze(request)
        );

        assertSame(failure, thrown);
        verify(urlValidator).validate(eq("https://example.com"), any(AnalysisDeadline.class));
        verify(dnsAnalyzer).analyze(eq("example.com"), any(AnalysisDeadline.class));
        verify(httpAnalyzer).followRedirects(eq("https://example.com"), any(AnalysisDeadline.class));
        verify(httpAnalyzer).analyzeResponse(redirectResult);
        verify(sslAnalyzer).analyze(eq("https://www.example.com/home"), eq("www.example.com"), any(AnalysisDeadline.class));
        verifyNoInteractions(securityHeadersAnalyzer, securityAssessmentCalculator);
    }

    @Test
    void shouldCompleteHttpAnalysisWithoutSslResult() {
        AnalyzeRequest request = new AnalyzeRequest("http://example.com");
        DnsAnalysisResult dnsAnalysisResult = mock(DnsAnalysisResult.class);
        HttpRedirectResult redirectResult = mock(HttpRedirectResult.class);
        HttpAnalysisResult httpAnalysisResult = mock(HttpAnalysisResult.class);
        SecurityHeadersAnalysisResult headersResult = mock(SecurityHeadersAnalysisResult.class);
        SecurityAssessmentResult assessmentResult = mock(SecurityAssessmentResult.class);
        HttpResponse<String> finalResponse = mock(HttpResponse.class);

        when(dnsAnalyzer.analyze(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(dnsAnalysisResult);
        when(httpAnalyzer.followRedirects(eq("http://example.com"), any(AnalysisDeadline.class))).thenReturn(redirectResult);
        when(httpAnalyzer.analyzeResponse(redirectResult)).thenReturn(httpAnalysisResult);
        when(httpAnalysisResult.getFinalUrl()).thenReturn("http://example.com");
        when(sslAnalyzer.analyze(eq("http://example.com"), eq("example.com"), any(AnalysisDeadline.class))).thenReturn(null);
        when(redirectResult.getFinalResponse()).thenReturn(finalResponse);
        when(securityHeadersAnalyzer.analyze(finalResponse)).thenReturn(headersResult);
        when(securityAssessmentCalculator.calculate(headersResult)).thenReturn(assessmentResult);

        AnalyzeResponse response = analyzeService.analyze(request);

        assertEquals("http://example.com", response.getUrl());
        assertNull(response.getSsl());
        assertSame(headersResult, response.getSecurityHeaders());
        assertSame(assessmentResult, response.getSecurityAssessment());
        verify(sslAnalyzer).analyze(eq("http://example.com"), eq("example.com"), any(AnalysisDeadline.class));
        verify(securityHeadersAnalyzer).analyze(finalResponse);
        verify(securityAssessmentCalculator).calculate(headersResult);
    }
}
