package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.config.SecurityConfig;
import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.dto.SaveAnalysisRequest;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisNotFoundException;
import io.github.raulperezmoreno71.threatintel.model.DnsAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.HttpAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.RedirectStep;
import io.github.raulperezmoreno71.threatintel.model.SecurityAssessmentResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeaderResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import io.github.raulperezmoreno71.threatintel.model.SslAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import io.github.raulperezmoreno71.threatintel.security.CustomAuthenticationEntryPoint;
import io.github.raulperezmoreno71.threatintel.security.JwtAuthenticationFilter;
import io.github.raulperezmoreno71.threatintel.service.AnalysisHistoryService;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.Collections;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static io.github.raulperezmoreno71.threatintel.support.CsrfRequestPostProcessors.csrfCookieAndHeader;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AnalysisHistoryController.class)
@ImportAutoConfiguration({ServletWebSecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class})
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, CustomAuthenticationEntryPoint.class})
class AnalysisHistoryControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AnalysisHistoryService analysisHistoryService;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void shouldReturnAnalysisById() throws Exception {
        AnalysisHistoryResponse response = mock(AnalysisHistoryResponse.class);

        when(response.getId()).thenReturn(1L);
        when(response.getUrl()).thenReturn("https://example.com");
        when(response.getDomain()).thenReturn("example.com");

        when(analysisHistoryService.getAnalysisById(1L)).thenReturn(response);

        mockMvc.perform(
                        get("/api/analyses/1")
                                .with(user("test@example.com"))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.url").value("https://example.com"))
                .andExpect(jsonPath("$.domain").value("example.com"));

        verify(analysisHistoryService).getAnalysisById(1L);
    }

    @Test
    void shouldReturnNotFoundWhenAnalysisToDeleteDoesNotExist() throws Exception {
        when(analysisHistoryService.getAnalysisById(1L)).thenThrow(new AnalysisNotFoundException(1L));

        mockMvc.perform(
                        get("/api/analyses/1")
                                .with(user("test@example.com"))
                )
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("Analysis not found with id: 1"))
                .andExpect(jsonPath("$.path").value("/api/analyses/1"));

        verify(analysisHistoryService).getAnalysisById(1L);
    }

    @Test
    void shouldReturnAllAnalyses() throws Exception {
        AnalysisHistoryResponse response1 = mock(AnalysisHistoryResponse.class);
        AnalysisHistoryResponse response2 = mock(AnalysisHistoryResponse.class);

        when(analysisHistoryService.getAllAnalyses()).thenReturn(List.of(response1, response2));

        when(response1.getId()).thenReturn(1L);
        when(response1.getUrl()).thenReturn("https://example.com");
        when(response1.getDomain()).thenReturn("example.com");

        when(response2.getId()).thenReturn(2L);
        when(response2.getUrl()).thenReturn("https://google.com");
        when(response2.getDomain()).thenReturn("google.com");

        mockMvc.perform(
                        get("/api/analyses")
                                .with(user("test@example.com"))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].url").value("https://example.com"))
                .andExpect(jsonPath("$[0].domain").value("example.com"))
                .andExpect(jsonPath("$[1].id").value(2))
                .andExpect(jsonPath("$[1].url").value("https://google.com"))
                .andExpect(jsonPath("$[1].domain").value("google.com"));

        verify(analysisHistoryService).getAllAnalyses();
    }

    @Test
    void shouldReturnEmptyListWhenThereAreNoAnalyses() throws Exception {
        when(analysisHistoryService.getAllAnalyses()).thenReturn(List.of());

        mockMvc.perform(
                        get("/api/analyses")
                                .with(user("test@example.com"))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        verify(analysisHistoryService).getAllAnalyses();
    }

    @Test
    void shouldDeleteAnalysisById() throws Exception {
        mockMvc.perform(
                        delete("/api/analyses/1")
                                .with(csrfCookieAndHeader())
                                .with(user("test@example.com"))
                )
                .andExpect(status().isNoContent());

        verify(analysisHistoryService).deleteAnalysisById(1L);
    }

    @Test
    void shouldThrowNotFoundWhenAnalysisToDeleteDoesNotExist() throws Exception {
        doThrow(new AnalysisNotFoundException(99L)).when(analysisHistoryService).deleteAnalysisById(99L);

        mockMvc.perform(
                        delete("/api/analyses/99")
                                .with(csrfCookieAndHeader())
                                .with(user("test@example.com"))
                )
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("Analysis not found with id: 99"))
                .andExpect(jsonPath("$.path").value("/api/analyses/99"));

        verify(analysisHistoryService).deleteAnalysisById(99L);
    }

    @Test
    void shouldSaveAnalysisSuccessfully() throws Exception {
        SaveAnalysisRequest request = createSaveAnalysisRequest();

        mockMvc.perform(
                        post("/api/analyses")
                                .with(csrfCookieAndHeader())
                                .with(user("test@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isCreated());

        verify(analysisHistoryService).saveAnalysis(
                argThat(saveRequest ->
                        "URL analyzed successfully".equals(saveRequest.getMessage())
                                && "http://example.com".equals(saveRequest.getUrl())
                                && "example.com".equals(saveRequest.getDomain())
                                && saveRequest.getDns() != null
                                && saveRequest.getHttp() != null
                                && saveRequest.getSsl() == null
                                && saveRequest.getSecurityHeaders() != null
                                && saveRequest.getSecurityAssessment() != null
                )
        );
    }

    @Test
    void shouldReturnBadRequestWhenSaveAnalysisJsonIsMalformed() throws Exception {
        mockMvc.perform(
                        post("/api/analyses")
                                .with(csrfCookieAndHeader())
                                .with(user("test@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Malformed JSON request"))
                .andExpect(jsonPath("$.path").value("/api/analyses"));

        verifyNoInteractions(analysisHistoryService);
    }

    @Test
    void shouldReturnBadRequestWhenSaveAnalysisBodyIsMissing() throws Exception {
        mockMvc.perform(
                        post("/api/analyses")
                                .with(csrfCookieAndHeader())
                                .with(user("test@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Malformed JSON request"))
                .andExpect(jsonPath("$.path").value("/api/analyses"));

        verifyNoInteractions(analysisHistoryService);
    }

    @Test
    void shouldReturnUnauthorizedWhenSavingAnalysisWithoutAuthentication() throws Exception {
        SaveAnalysisRequest request = createSaveAnalysisRequest();

        mockMvc.perform(
                        post("/api/analyses")
                                .with(csrfCookieAndHeader())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication is required"))
                .andExpect(jsonPath("$.path").value("/api/analyses"));

        verifyNoInteractions(analysisHistoryService);
    }

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
        ObjectNode report = (ObjectNode) objectMapper.valueToTree(createSaveAnalysisRequest());
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

        mockMvc.perform(post("/api/analyses")
                        .with(user("test@example.com"))
                        .with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(report)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.path").value("/api/analyses"))
                .andExpect(jsonPath("$.message", containsString(field)));

        verifyNoInteractions(analysisHistoryService);
    }

    @Test
    void shouldAllowExpiredCertificateAndNullableOptionalHttpFields() throws Exception {
        SaveAnalysisRequest request = createSaveAnalysisRequest();
        request.setSsl(new SslAnalysisResult(
                "CN=Example CA", "CN=example.com", LocalDate.of(2025, 1, 1),
                LocalDate.of(2026, 1, 1), -10, SslStatus.CRITICAL, null));
        request.getHttp().setContentLength(null);
        request.getHttp().setServer(null);
        request.getHttp().setContentType(null);

        mockMvc.perform(post("/api/analyses")
                        .with(user("test@example.com"))
                        .with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 100})
    void shouldAcceptScoreBoundariesAndMaximumRequestChain(int score) throws Exception {
        SaveAnalysisRequest request = createSaveAnalysisRequest();
        request.getSecurityAssessment().setScore(score);
        request.getSecurityAssessment().setGrade(score == 0 ? "F" : "A");
        request.getHttp().setRedirectChain(Collections.nCopies(11, request.getHttp().getRedirectChain().getFirst()));
        request.getDns().setIps(Collections.nCopies(64, "1.1.1.1"));

        mockMvc.perform(post("/api/analyses")
                        .with(user("test@example.com"))
                        .with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    private SaveAnalysisRequest createSaveAnalysisRequest() {
        SecurityHeaderResult goodHeader = new SecurityHeaderResult(
                true,
                "valid-value",
                SecurityStatus.GOOD,
                null
        );

        return new SaveAnalysisRequest(
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
