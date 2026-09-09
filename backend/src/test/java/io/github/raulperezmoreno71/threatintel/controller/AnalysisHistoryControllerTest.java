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
import io.github.raulperezmoreno71.threatintel.security.CustomAuthenticationEntryPoint;
import io.github.raulperezmoreno71.threatintel.security.JwtAuthenticationFilter;
import io.github.raulperezmoreno71.threatintel.service.AnalysisHistoryService;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import org.junit.jupiter.api.Test;
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

import java.util.List;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
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
