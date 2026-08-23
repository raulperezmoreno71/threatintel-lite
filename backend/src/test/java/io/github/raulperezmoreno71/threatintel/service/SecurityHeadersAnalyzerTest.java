package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.SecurityHeaderResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityHeadersAnalyzerTest {

    private SecurityHeadersAnalyzer analyzer;
    private HttpResponse<String> response;

    @BeforeEach
    void setUp() {
        analyzer = new SecurityHeadersAnalyzer();

        response = mock(HttpResponse.class);
    }

    @Test
    void shouldReturnGoodStatusWhenAllSecurityHeadersAreValid() {
        configureHeaders(
                Map.of(
                        "Strict-Transport-Security",
                        List.of("max-age=31536000"),

                        "Content-Security-Policy",
                        List.of("default-src 'self'"),

                        "X-Frame-Options",
                        List.of("DENY"),

                        "X-Content-Type-Options",
                        List.of("nosniff"),

                        "Referrer-Policy",
                        List.of("strict-origin-when-cross-origin"),

                        "Permissions-Policy",
                        List.of("camera=(), microphone=()")
                )
        );

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertGoodHeaders(result.getStrictTransportSecurity(), "max-age=31536000");
        assertGoodHeaders(result.getContentSecurityPolicy(), "default-src 'self'");
        assertGoodHeaders(result.getXFrameOptions(), "DENY");
        assertGoodHeaders(result.getXContentTypeOptions(), "nosniff");
        assertGoodHeaders(result.getReferrerPolicy(), "strict-origin-when-cross-origin");
        assertGoodHeaders(result.getPermissionsPolicy(), "camera=(), microphone=()");
    }

    @Test
    void shouldReturnMissingStatusWhenAllSecurityHeadersAreAbsent() {
        configureHeaders(
                Map.of()
        );

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertMissingHeader(result.getStrictTransportSecurity());
        assertMissingHeader(result.getContentSecurityPolicy());
        assertMissingHeader(result.getXFrameOptions());
        assertMissingHeader(result.getXContentTypeOptions());
        assertMissingHeader(result.getReferrerPolicy());
        assertMissingHeader(result.getPermissionsPolicy());
    }

    @ParameterizedTest(name = "[{index}] {0} -> {1}")
    @CsvSource({
            "max-age=31536000, GOOD",
            "max-age=31535999, WARNING",
            "max-age=0, WARNING",
            "max-age=-1, WARNING",
            "max-age=abc, WARNING",
            "includeSubDomains, WARNING"
    })
    void shouldAnalyzeStrictTransportSecurityCorrectly(String hstsValue, SecurityStatus expectedStatus) {
        configureHeaders(validHeadersWithHsts(hstsValue));

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertHeaderResult(result.getStrictTransportSecurity(), hstsValue, expectedStatus);
    }

    @ParameterizedTest(name = "[{index}] CSP={0} -> {1}")
    @CsvSource({
            "'default-src ''self''', GOOD",
            "'', WARNING",
            "'script-src ''unsafe-eval''', WARNING",
            "'script-src ''unsafe-inline''', WARNING",
            "'img-src ''self''', WARNING",
            "'default-src *', WARNING"
    })
    void shouldAnalyzeContentSecurityPolicyCorrectly(String cspValue, SecurityStatus expectedStatus) {
        configureHeaders(validHeadersWithCsp(cspValue));

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertHeaderResult(result.getContentSecurityPolicy(), cspValue, expectedStatus);
    }

    @ParameterizedTest(name = "[{index}] X-Frame-Options={0} -> {1}")
    @CsvSource({
            "DENY, GOOD",
            "SAMEORIGIN, GOOD",
            "'ALLOW-FROM https://example.com', WARNING",
            "INVALID, WARNING"
    })
    void shouldAnalyzeXFrameOptionsCorrectly(String xFrameOptionsValue, SecurityStatus expectedStatus) {
        configureHeaders(validHeadersWithXFrameOptions(xFrameOptionsValue));

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertHeaderResult(result.getXFrameOptions(), xFrameOptionsValue, expectedStatus);
    }

    @ParameterizedTest(name = "[{index}] X-Content-Type-Options={0} -> {1}")
    @CsvSource({
            "nosniff, GOOD",
            "NoSnIfF, GOOD",
            "invalid, WARNING"
    })
    void shouldAnalyzeXContentTypeOptionsCorrectly(String xContentTypeOptionsValue, SecurityStatus expectedStatus) {
        configureHeaders(validHeadersWithXContentTypeOptions(xContentTypeOptionsValue));

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertHeaderResult(result.getXContentTypeOptions(), xContentTypeOptionsValue, expectedStatus);
    }

    @ParameterizedTest(name = "[{index}] Referrer-Policy={0} -> {1}")
    @CsvSource({
            "strict-origin-when-cross-origin, GOOD",
            "strict-origin, GOOD",
            "same-origin, GOOD",
            "no-referrer, GOOD",
            "origin, WARNING",
            "origin-when-cross-origin, WARNING",
            "unsafe-url, WARNING",
            "no-referrer-when-downgrade, WARNING",
            "invalid-policy, WARNING",
            "'invalid-policy, strict-origin', GOOD"
    })
    void shouldAnalyzeReferrerPolicyCorrectly(String referrerPolicyValue, SecurityStatus expectedStatus) {
        configureHeaders(validHeadersWithReferrerPolicy(referrerPolicyValue));

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertHeaderResult(result.getReferrerPolicy(), referrerPolicyValue, expectedStatus);
    }

    @ParameterizedTest(name = "[{index}] Permission-Policy={0} ->  {1}")
    @CsvSource({
            "'camera=(), microphone=()', GOOD",
            "'', WARNING",
            "'camera=(''none'')', WARNING",
            "camera, WARNING",
            "camera=(), GOOD"
    })
    void shouldAnalyzePermissionPolicyCorrectly(String permissionPolicyValue, SecurityStatus expectedStatus) {
        configureHeaders(validHeadersWithPermissionsPolicy(permissionPolicyValue));

        SecurityHeadersAnalysisResult result = analyzer.analyze(response);

        assertHeaderResult(result.getPermissionsPolicy(), permissionPolicyValue, expectedStatus);
    }

    private Map<String, List<String>> validHeadersWithPermissionsPolicy(String permissionsPolicyValue) {
        return Map.of(
                "Strict-Transport-Security",
                List.of("max-age=31536000"),

                "Content-Security-Policy",
                List.of("default-src 'self'"),

                "X-Frame-Options",
                List.of("DENY"),

                "X-Content-Type-Options",
                List.of("nosniff"),

                "Referrer-Policy",
                List.of("strict-origin-when-cross-origin"),

                "Permissions-Policy",
                List.of(permissionsPolicyValue)
        );
    }

    private Map<String, List<String>> validHeadersWithReferrerPolicy(String referrerPolicyValue) {
        return Map.of(
                "Strict-Transport-Security",
                List.of("max-age=31536000"),

                "Content-Security-Policy",
                List.of("default-src 'self'"),

                "X-Frame-Options",
                List.of("DENY"),

                "X-Content-Type-Options",
                List.of("nosniff"),

                "Referrer-Policy",
                List.of(referrerPolicyValue),

                "Permissions-Policy",
                List.of("camera=(), microphone=()")
        );
    }

    private Map<String, List<String>> validHeadersWithXContentTypeOptions(String xContentTypeOptionsValue) {
        return Map.of(
                "Strict-Transport-Security",
                List.of("max-age=31536000"),

                "Content-Security-Policy",
                List.of("default-src 'self'"),

                "X-Frame-Options",
                List.of("DENY"),

                "X-Content-Type-Options",
                List.of(xContentTypeOptionsValue),

                "Referrer-Policy",
                List.of("strict-origin-when-cross-origin"),

                "Permissions-Policy",
                List.of("camera=(), microphone=()")
        );
    }

    private Map<String, List<String>> validHeadersWithXFrameOptions(String xFrameOptionsValue) {
        return Map.of(
                "Strict-Transport-Security",
                List.of("max-age=31536000"),

                "Content-Security-Policy",
                List.of("default-src 'self'"),

                "X-Frame-Options",
                List.of(xFrameOptionsValue),

                "X-Content-Type-Options",
                List.of("nosniff"),

                "Referrer-Policy",
                List.of("strict-origin-when-cross-origin"),

                "Permissions-Policy",
                List.of("camera=(), microphone=()")
        );
    }

    private Map<String, List<String>> validHeadersWithCsp(String cspValue) {
        return Map.of(
                "Strict-Transport-Security",
                List.of("max-age=31536000"),

                "Content-Security-Policy",
                List.of(cspValue),

                "X-Frame-Options",
                List.of("DENY"),

                "X-Content-Type-Options",
                List.of("nosniff"),

                "Referrer-Policy",
                List.of("strict-origin-when-cross-origin"),

                "Permissions-Policy",
                List.of("camera=(), microphone=()")
        );
    }

    private Map<String, List<String>> validHeadersWithHsts(String hstsValue) {
        return Map.of(
                "Strict-Transport-Security",
                List.of(hstsValue),

                "Content-Security-Policy",
                List.of("default-src 'self'"),

                "X-Frame-Options",
                List.of("DENY"),

                "X-Content-Type-Options",
                List.of("nosniff"),

                "Referrer-Policy",
                List.of("strict-origin-when-cross-origin"),

                "Permissions-Policy",
                List.of("camera=(), microphone=()")
        );
    }

    private void assertHeaderResult(SecurityHeaderResult header, String expectedValue, SecurityStatus expectedStatus) {
        assertTrue(header.isPresent());
        assertEquals(expectedValue, header.getValue());
        assertEquals(expectedStatus, header.getStatus());

        if (expectedStatus == SecurityStatus.GOOD) {
            assertNull(header.getRecommendation());
        } else {
            assertNotNull(header.getRecommendation());
        }
    }

    private void configureHeaders(Map<String, List<String>> headerValues) {
        HttpHeaders headers = HttpHeaders.of(
                headerValues,
                (name, value) -> true
        );

        when(response.headers()).thenReturn(headers);
    }

    private void assertMissingHeader(SecurityHeaderResult header) {
        assertFalse(header.isPresent());
        assertNull(header.getValue());
        assertEquals(SecurityStatus.MISSING, header.getStatus());
        assertNotNull(header.getRecommendation());
    }

    private void assertGoodHeaders(SecurityHeaderResult header, String expectedValue) {
        assertTrue(header.isPresent());
        assertEquals(expectedValue, header.getValue());
        assertEquals(SecurityStatus.GOOD, header.getStatus());
        assertNull(header.getRecommendation());
    }
}
