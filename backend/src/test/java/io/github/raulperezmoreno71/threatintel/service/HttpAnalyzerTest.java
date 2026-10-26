package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.HttpRequestException;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import io.github.raulperezmoreno71.threatintel.exception.TooManyRedirectsException;
import io.github.raulperezmoreno71.threatintel.model.HttpAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.HttpRedirectResult;
import io.github.raulperezmoreno71.threatintel.model.RedirectStep;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class HttpAnalyzerTest {

    private HttpAnalyzer httpAnalyzer;
    private PinnedHttpTransport httpClient;
    private DnsAnalyzer dnsAnalyzer;

    @BeforeEach
    void setUp() throws Exception {
        httpClient = mock(PinnedHttpTransport.class);
        dnsAnalyzer = mock(DnsAnalyzer.class);
        when(dnsAnalyzer.resolve(anyString(), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName("8.8.8.8")});
        httpAnalyzer = new HttpAnalyzer(httpClient, new UrlValidator(dnsAnalyzer));
    }

    @Test
    void shouldNotRestartBudgetForRedirects() throws Exception {
        AtomicLong ticker = new AtomicLong();
        AnalysisDeadline deadline = new AnalysisDeadline(Duration.ofSeconds(15), ticker::get);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(302);
        when(response.headers()).thenReturn(HttpHeaders.of(Map.of("Location", List.of("/next")), (name, value) -> true));
        when(httpClient.get(any(ValidatedUrl.class), same(deadline))).thenAnswer(invocation -> {
            ticker.addAndGet(Duration.ofSeconds(8).toNanos());
            return response;
        });

        assertThrows(AnalysisTimeoutException.class, () -> httpAnalyzer.followRedirects("https://example.com", deadline));

        verify(httpClient, times(2)).get(any(ValidatedUrl.class), same(deadline));
    }

    @Test
    void shouldNotWrapSharedTimeoutAsAnHttpFailure() throws Exception {
        AnalysisTimeoutException expired = new AnalysisTimeoutException();
        when(httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))).thenThrow(expired);

        assertSame(expired, assertThrows(AnalysisTimeoutException.class,
                () -> httpAnalyzer.followRedirects("https://example.com")));
    }

    @Test
    void shouldPassApprovedDnsSnapshotToTransportWithoutResolvingAgain() throws Exception {
        InetAddress approved = InetAddress.getByName("8.8.8.8");
        when(dnsAnalyzer.resolve(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(
                new InetAddress[]{approved}, new InetAddress[]{InetAddress.getByName("127.0.0.1")}
        );
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(HttpHeaders.of(Map.of(), (name, value) -> true));
        when(httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))).thenReturn(response);

        httpAnalyzer.followRedirects("https://example.com/path");

        ArgumentCaptor<ValidatedUrl> target = ArgumentCaptor.forClass(ValidatedUrl.class);
        verify(httpClient).get(target.capture(), any(AnalysisDeadline.class));
        assertEquals("https://example.com/path", target.getValue().uri().toString());
        assertEquals(List.of(approved), target.getValue().addresses());
        verify(dnsAnalyzer, times(1)).resolve(eq("example.com"), any(AnalysisDeadline.class));
    }

    @Test
    void shouldRejectPrivateDestinationBeforeSendingRequest() throws Exception {
        when(dnsAnalyzer.resolve(eq("127.0.0.1"), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName("127.0.0.1")});

        assertThrows(IllegalArgumentException.class, () -> httpAnalyzer.followRedirects("http://127.0.0.1"));

        verifyNoInteractions(httpClient);
    }

    @Test
    void shouldRejectRedirectResolvingToPrivateAddress() throws Exception {
        when(dnsAnalyzer.resolve(eq("internal.example"), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName("10.0.0.1")});
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(302);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Location", List.of("https://internal.example")), (name, value) -> true
        ));
        when(httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))).thenReturn(response);

        assertThrows(IllegalArgumentException.class, () -> httpAnalyzer.followRedirects("https://example.com"));

        verify(httpClient, times(1)).get(any(ValidatedUrl.class), any(AnalysisDeadline.class));
    }

    @Test
    void shouldRejectNonStandardPortBeforeSendingRequest() {
        assertThrows(
                IllegalArgumentException.class,
                () -> httpAnalyzer.followRedirects("http://example.com:8080")
        );

        verifyNoInteractions(httpClient);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://example.com:8443", "//example.com:8443/final"})
    void shouldRejectRedirectToNonStandardPort(String location) throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(302);
        when(response.headers()).thenReturn(HttpHeaders.of(
                Map.of("Location", List.of(location)),
                (name, value) -> true
        ));
        when(httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class)))
                .thenReturn(response);

        assertThrows(
                IllegalArgumentException.class,
                () -> httpAnalyzer.followRedirects("https://example.com")
        );

        verify(httpClient, times(1)).get(any(ValidatedUrl.class), any(AnalysisDeadline.class));
    }

    @Test
    void shouldAnalyzeHttpResponseCorrectly() {
        HttpResponse<String> response = mock(HttpResponse.class);

        HttpHeaders headers = HttpHeaders.of(
                Map.of(
                        "Content-Type", List.of("text/html"),
                        "Server", List.of("nginx"),
                        "Content-Length", List.of("1250")
                ),
                (name, value) -> true
        );

        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(headers);

        List<RedirectStep> redirectChain = List.of(
                new RedirectStep(
                        "http://example.com",
                        301,
                        "https://example.com",
                        50
                ),
                new RedirectStep(
                        "https://example.com",
                        200,
                        null,
                        100
                )
        );

        HttpRedirectResult redirectResult = new HttpRedirectResult(
                response,
                redirectChain,
                150
        );

        HttpAnalysisResult result = httpAnalyzer.analyzeResponse(redirectResult);

        assertEquals(200, result.getStatusCode());
        assertEquals("text/html", result.getContentType());
        assertEquals("nginx", result.getServer());
        assertEquals(1250L, result.getContentLength());
        assertEquals("https://example.com", result.getFinalUrl());
        assertEquals(150, result.getTotalResponseTimeMs());
        assertEquals(redirectChain, result.getRedirectChain());
    }

    @Test
    void shouldReturnNullWhenOptionalHttpHeadersAreMissing() {
        HttpResponse<String> response = mock(HttpResponse.class);

        HttpHeaders emptyHeaders = HttpHeaders.of(
                Map.of(),
                (name, value) -> true
        );

        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(emptyHeaders);

        List<RedirectStep> redirectChain = List.of(
                new RedirectStep(
                        "https://example.com",
                        200,
                        null,
                        100
                )
        );

        HttpRedirectResult redirectResult = new HttpRedirectResult(
                response,
                redirectChain,
                100
        );

        HttpAnalysisResult result = httpAnalyzer.analyzeResponse(redirectResult);

        assertEquals(200, result.getStatusCode());
        assertEquals("https://example.com", result.getFinalUrl());
        assertEquals(100, result.getTotalResponseTimeMs());

        assertNull(result.getContentLength());
        assertNull(result.getContentType());
        assertNull(result.getServer());
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 303, 307, 308})
    void shouldFollowEverySupportedRedirectStatus(int redirectStatus) throws Exception {
        HttpResponse<String> redirectResponse = mock(HttpResponse.class);
        HttpResponse<String> finalResponse = mock(HttpResponse.class);

        HttpHeaders redirectHeaders = HttpHeaders.of(
                Map.of(
                        "Location",
                        List.of("https://example.com")
                ),
                (name, value) -> true
        );

        HttpHeaders finalHeaders = HttpHeaders.of(
                Map.of(),
                (name, value) -> true
        );

        when(redirectResponse.statusCode()).thenReturn(redirectStatus);
        when(redirectResponse.headers()).thenReturn(redirectHeaders);

        when(finalResponse.statusCode()).thenReturn(200);
        when(finalResponse.headers()).thenReturn(finalHeaders);

        when(httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))
        ).thenReturn(
                redirectResponse,
                finalResponse
        );

        HttpRedirectResult result = httpAnalyzer.followRedirects("http://example.com");

        assertEquals(2, result.getRedirectChain().size());

        RedirectStep firstStep = result.getRedirectChain().get(0);
        RedirectStep secondStep = result.getRedirectChain().get(1);

        assertEquals("http://example.com", firstStep.getUrl());
        assertEquals(redirectStatus, firstStep.getStatusCode());
        assertEquals("https://example.com", firstStep.getLocation());

        assertEquals("https://example.com", secondStep.getUrl());
        assertEquals(200, secondStep.getStatusCode());
        assertNull(secondStep.getLocation());

        assertSame(finalResponse, result.getFinalResponse());
    }

    @Test
    void shouldStopWhenRedirectResponseHasNoLocationHeader() throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);
        HttpHeaders headers = HttpHeaders.of(Map.of(), (name, value) -> true);

        when(response.statusCode()).thenReturn(302);
        when(response.headers()).thenReturn(headers);
        when(httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))).thenReturn(response);

        HttpRedirectResult result = httpAnalyzer.followRedirects("https://example.com/start");

        assertEquals(1, result.getRedirectChain().size());
        assertEquals("https://example.com/start", result.getRedirectChain().get(0).getUrl());
        assertEquals(302, result.getRedirectChain().get(0).getStatusCode());
        assertNull(result.getRedirectChain().get(0).getLocation());
        assertSame(response, result.getFinalResponse());
        verify(httpClient).get(any(ValidatedUrl.class), any(AnalysisDeadline.class));
    }

    @Test
    void shouldRejectNonNumericContentLength() {
        HttpResponse<String> response = mock(HttpResponse.class);
        HttpHeaders headers = HttpHeaders.of(
                Map.of("Content-Length", List.of("not-a-number")),
                (name, value) -> true
        );
        HttpRedirectResult redirectResult = new HttpRedirectResult(
                response,
                List.of(new RedirectStep("https://example.com", 200, null, 10)),
                10
        );

        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(headers);

        assertThrows(
                NumberFormatException.class,
                () -> httpAnalyzer.analyzeResponse(redirectResult)
        );
    }

    @Test
    void shouldReturnSingleStepWhenResponseIsNotARedirect() throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);

        HttpHeaders headers = HttpHeaders.of(
                Map.of(),
                (name, value) -> true
        );

        when(response.statusCode()).thenReturn(200);
        when(response.headers()).thenReturn(headers);

        when(
                httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))
        ).thenReturn(response);

        HttpRedirectResult result = httpAnalyzer.followRedirects("https://example.com");

        assertEquals(1, result.getRedirectChain().size());

        RedirectStep step = result.getRedirectChain().get(0);

        assertEquals("https://example.com", step.getUrl());
        assertEquals(200, step.getStatusCode());
        assertNull(step.getLocation());
        assertSame(response, result.getFinalResponse());

        verify(httpClient, times(1)).get(any(ValidatedUrl.class), any(AnalysisDeadline.class));
    }

    @Test
    void shouldThrowHttpRequestExceptionWhenHttpRequestFails() throws Exception {
        IOException cause = new IOException("Connection failed");

        when(
                httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))
        ).thenThrow(cause);

        HttpRequestException exception = assertThrows(
                HttpRequestException.class,
                () -> httpAnalyzer.followRedirects(
                        "http://example.com"
                )
        );

        assertEquals("Could not send HTTP request", exception.getMessage());

        assertSame(cause, exception.getCause());
    }

    @Test
    void shouldResolveRelativeRedirectLocation() throws Exception {
        HttpResponse<String> redirectResponse = mock(HttpResponse.class);
        HttpResponse<String> finalResponse = mock(HttpResponse.class);

        HttpHeaders redirectHeaders = HttpHeaders.of(
                Map.of(
                        "Location",
                        List.of("/final")
                ),
                (name, value) -> true
        );

        HttpHeaders finalHeaders = HttpHeaders.of(
                Map.of(),
                (name, value) -> true
        );

        when(redirectResponse.statusCode()).thenReturn(302);
        when(redirectResponse.headers()).thenReturn(redirectHeaders);

        when(finalResponse.statusCode()).thenReturn(200);
        when(finalResponse.headers()).thenReturn(finalHeaders);

        when(
                httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))
        ).thenReturn(
                redirectResponse,
                finalResponse
        );

        HttpRedirectResult result = httpAnalyzer.followRedirects("https://example.com/start");

        assertEquals(2, result.getRedirectChain().size());

        RedirectStep firstStep = result.getRedirectChain().get(0);
        RedirectStep secondStep = result.getRedirectChain().get(1);

        assertEquals("https://example.com/start", firstStep.getUrl());
        assertEquals(302, firstStep.getStatusCode());
        assertEquals("/final", firstStep.getLocation());

        assertEquals("https://example.com/final", secondStep.getUrl());
        assertEquals(200, secondStep.getStatusCode());
        assertNull(secondStep.getLocation());

        assertSame(finalResponse, result.getFinalResponse());

        long accumulatedTime = result.getRedirectChain().stream()
                .mapToLong(RedirectStep::getResponseTimeMs)
                .sum();
        assertEquals(accumulatedTime, result.getTotalResponseTimeMs());
        assertTrue(result.getTotalResponseTimeMs() >= 0);

        verify(httpClient, times(2)).get(any(ValidatedUrl.class), any(AnalysisDeadline.class));
    }

    @Test
    void shouldThrowTooManyRedirectsExceptionWhenMaximumRedirectsAreExceeded() throws Exception {
        HttpResponse<String> redirectResponse = mock(HttpResponse.class);

        HttpHeaders redirectHeaders = HttpHeaders.of(
                Map.of(
                        "Location",
                        List.of("/next")
                ),
                (name, value) -> true
        );

        when(redirectResponse.statusCode()).thenReturn(302);
        when(redirectResponse.headers()).thenReturn(redirectHeaders);

        when(
                httpClient.get(any(ValidatedUrl.class), any(AnalysisDeadline.class))
        ).thenReturn(redirectResponse);

        TooManyRedirectsException exception = assertThrows(
                TooManyRedirectsException.class,
                () -> httpAnalyzer.followRedirects("https://example.com/start")
        );

        assertEquals("Maximum number of redirects exceeded", exception.getMessage());

        verify(httpClient, times(11)).get(any(ValidatedUrl.class), any(AnalysisDeadline.class));
    }
}
