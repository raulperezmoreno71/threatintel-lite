package io.github.raulperezmoreno71.threatintel.service;
import io.github.raulperezmoreno71.threatintel.dto.*;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.exception.PendingAnalysisException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import java.time.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class PendingAnalysisValidationTest {
    private final JsonMapper objectMapper = JsonMapper.builder().findAndAddModules().build();
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    private final PendingAnalysisStore store = new PendingAnalysisStore(900, 5, 500, 131072, Clock.systemUTC(), objectMapper, validator);
    static Stream<Arguments> invalidSavedReports() {
        return Stream.of(
                Arguments.of("/url", null, "url"),
                Arguments.of("/url", " ", "url"),
                Arguments.of("/url", "x".repeat(256), "url"),
                Arguments.of("/domain", null, "domain"),
                Arguments.of("/domain", "x".repeat(254), "domain"),
                Arguments.of("/message", "x".repeat(256), "message"),
                Arguments.of("/dns", null, "dns"),
                Arguments.of("/http", null, "http"),
                Arguments.of("/securityHeaders", null, "securityHeaders"),
                Arguments.of("/securityAssessment", null, "securityAssessment"),
                Arguments.of("/dns/ips", null, "dns.ips"),
                Arguments.of("/dns/ips", List.of(), "dns.ips"),
                Arguments.of("/dns/ips", Collections.nCopies(65, "1.1.1.1"), "dns.ips"),
                Arguments.of("/dns/ips", Collections.singletonList(null), "dns.ips"),
                Arguments.of("/dns/ips", List.of(" "), "dns.ips"),
                Arguments.of("/dns/ips", List.of("x".repeat(46)), "dns.ips"),
                Arguments.of("/http/statusCode", 99, "http.statusCode"),
                Arguments.of("/http/statusCode", 600, "http.statusCode"),
                Arguments.of("/http/totalResponseTimeMs", -1, "http.totalResponseTimeMs"),
                Arguments.of("/http/totalResponseTimeMs", "<missing>", "http.totalResponseTimeMs"),
                Arguments.of("/http/contentLength", -1, "http.contentLength"),
                Arguments.of("/http/finalUrl", " ", "http.finalUrl"),
                Arguments.of("/http/finalUrl", "x".repeat(256), "http.finalUrl"),
                Arguments.of("/http/server", "x".repeat(256), "http.server"),
                Arguments.of("/http/contentType", "x".repeat(256), "http.contentType"),
                Arguments.of("/http/redirectChain", null, "http.redirectChain"),
                Arguments.of("/http/redirectChain", List.of(), "http.redirectChain"),
                Arguments.of("/http/redirectChain", Collections.nCopies(12, Map.of()), "http.redirectChain"),
                Arguments.of("/http/redirectChain", Collections.singletonList(null), "http.redirectChain"),
                Arguments.of("/http/redirectChain/0/statusCode", 600, "http.redirectChain[0].statusCode"),
                Arguments.of("/http/redirectChain/0/url", " ", "http.redirectChain[0].url"),
                Arguments.of("/http/redirectChain/0/location", "x".repeat(256), "http.redirectChain[0].location"),
                Arguments.of("/http/redirectChain/0/responseTimeMs", -1, "http.redirectChain[0].responseTimeMs"),
                Arguments.of("/securityAssessment/score", -1, "securityAssessment.score"),
                Arguments.of("/securityAssessment/score", 101, "securityAssessment.score"),
                Arguments.of("/securityAssessment/score", "<missing>", "securityAssessment.score"),
                Arguments.of("/securityAssessment/score", null, "securityAssessment.score"),
                Arguments.of("/securityAssessment/grade", "E", "securityAssessment.grade"),
                Arguments.of("/securityAssessment/goodHeaders", 7, "securityAssessment.goodHeaders"),
                Arguments.of("/securityAssessment/warningHeaders", -1, "securityAssessment.warningHeaders"),
                Arguments.of("/securityAssessment/missingHeaders", 7, "securityAssessment.missingHeaders"),
                Arguments.of("/securityHeaders/contentSecurityPolicy", null, "securityHeaders.contentSecurityPolicy"),
                Arguments.of("/securityHeaders/strictTransportSecurity", null, "securityHeaders.strictTransportSecurity"),
                Arguments.of("/securityHeaders/xFrameOptions", null, "securityHeaders.xFrameOptions"),
                Arguments.of("/securityHeaders/xContentTypeOptions", null, "securityHeaders.xContentTypeOptions"),
                Arguments.of("/securityHeaders/referrerPolicy", null, "securityHeaders.referrerPolicy"),
                Arguments.of("/securityHeaders/permissionsPolicy", null, "securityHeaders.permissionsPolicy"),
                Arguments.of("/securityHeaders/contentSecurityPolicy/status", null, "securityHeaders.contentSecurityPolicy.status"),
                Arguments.of("/securityHeaders/contentSecurityPolicy/present", "<missing>", "securityHeaders.contentSecurityPolicy.present"),
                Arguments.of("/securityHeaders/contentSecurityPolicy/value", "x".repeat(8193), "securityHeaders.contentSecurityPolicy.value"),
                Arguments.of("/securityHeaders/contentSecurityPolicy/recommendation", "x".repeat(2049), "securityHeaders.contentSecurityPolicy.recommendation"),
                Arguments.of("/ssl/issuer", " ", "ssl.issuer"),
                Arguments.of("/ssl/subject", "x".repeat(256), "ssl.subject"),
                Arguments.of("/ssl/validFrom", null, "ssl.validFrom"),
                Arguments.of("/ssl/validUntil", null, "ssl.validUntil"),
                Arguments.of("/ssl/status", null, "ssl.status"),
                Arguments.of("/ssl/daysUntilExpiration", "<missing>", "ssl.daysUntilExpiration"),
                Arguments.of("/ssl/recommendation", "x".repeat(256), "ssl.recommendation")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidSavedReports")
    void shouldRejectInvalidNestedReportBeforeSaving(String pointer, Object value, String field) throws Exception {
        ObjectNode report = (ObjectNode) objectMapper.valueToTree(createAnalysisSnapshot());
        if (pointer.startsWith("/ssl/")) {
            report.set("ssl", objectMapper.valueToTree(Map.of(
                    "issuer", "CN=Example CA", "subject", "CN=example.com",
                    "validFrom", "2025-01-01", "validUntil", "2026-01-01",
                    "daysUntilExpiration", -10, "status", "CRITICAL")));
        }
        int lastSlash = pointer.lastIndexOf('/');
        ObjectNode parent = (ObjectNode) report.at(pointer.substring(0, lastSlash));
        String key = pointer.substring(lastSlash + 1);
        if ("<missing>".equals(value)) {
            parent.remove(key);
        } else {
            parent.set(key, objectMapper.valueToTree(value));
        }

        var snapshot = objectMapper.treeToValue(report, AnalysisSnapshot.class);
        assertTrue(validator.validate(snapshot).stream().anyMatch(error -> error.getPropertyPath().toString().startsWith(field)), field);
        assertThrows(PendingAnalysisException.class, () -> store.validateForPersistence(snapshot));
    }

    @Test
    void shouldAllowExpiredCertificateAndNullableOptionalHttpFields() throws Exception {
        AnalysisSnapshot request = createAnalysisSnapshot();
        request.setSsl(new SslAnalysisResult(
                "CN=Example CA", "CN=example.com", LocalDate.of(2025, 1, 1),
                LocalDate.of(2026, 1, 1), -10, SslStatus.CRITICAL, null));
        request.getHttp().setContentLength(null);
        request.getHttp().setServer(null);
        request.getHttp().setContentType(null);

        assertDoesNotThrow(() -> store.validateForPersistence(request));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 100})
    void shouldAcceptScoreBoundariesAndMaximumRequestChain(int score) throws Exception {
        AnalysisSnapshot request = createAnalysisSnapshot();
        request.getSecurityAssessment().setScore(score);
        request.getSecurityAssessment().setGrade(score == 0 ? "F" : "A");
        request.getHttp().setRedirectChain(Collections.nCopies(11, request.getHttp().getRedirectChain().getFirst()));
        request.getDns().setIps(Collections.nCopies(64, "1.1.1.1"));

        assertDoesNotThrow(() -> store.validateForPersistence(request));
    }

    private AnalysisSnapshot createAnalysisSnapshot() {
        SecurityHeaderResult goodHeader = new SecurityHeaderResult(
                true,
                "valid-value",
                SecurityStatus.GOOD,
                null
        );

        return new AnalysisSnapshot(
                "URL analyzed successfully",
                "http://example.com",
                "example.com",
                new DnsAnalysisResult(List.of("93.184.216.34")),
                new HttpAnalysisResult(
                        200,
                        "text/html",
                        "nginx",
                        1500L,
                        "http://example.com",
                        120L,
                        List.of(
                                new RedirectStep(
                                        "http://example.com",
                                        200,
                                        null,
                                        120L
                                )
                        )
                ),
                null,
                new SecurityHeadersAnalysisResult(
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader
                ),
                new SecurityAssessmentResult(
                        100,
                        "A",
                        6,
                        0,
                        0
                )
        );
    }
}
