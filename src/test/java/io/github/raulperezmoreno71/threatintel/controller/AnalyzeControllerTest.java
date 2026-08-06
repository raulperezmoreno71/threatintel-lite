package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.service.AnalyzeService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AnalyzeController.class)
class AnalyzeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AnalyzeService analyzeService;

    @Test
    void shouldReturnOkWhenUrlIsAnalyzedSuccessfully() throws Exception {
        AnalyzeRequest request = new AnalyzeRequest("https://example.com");

        AnalyzeResponse serviceResponse = new AnalyzeResponse(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                null,
                null,
                null,
                null,
                null
        );

        when(analyzeService.analyze(any(AnalyzeRequest.class))).thenReturn(serviceResponse);

        mockMvc.perform(
                post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$.message").value("URL analyzed successfully")
                )
                .andExpect(
                        jsonPath("$.url").value("https://example.com")
                )
                .andExpect(
                        jsonPath("$.domain").value("example.com")
                );

        verify(analyzeService).analyze(
                argThat(
                        analyzeRequest -> "https://example.com".equals(analyzeRequest.getUrl())
                )
        );
    }

    @Test
    void shouldReturnBadRequestWhenUrlIsInvalid() throws Exception {
        AnalyzeRequest request = new AnalyzeRequest("  ");

        when(analyzeService.analyze(any(AnalyzeRequest.class))).thenThrow(
                new IllegalArgumentException("URL cannot be null or blank")
        );

        mockMvc.perform(
                post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isBadRequest())
                .andExpect(
                        jsonPath("$.status").value(400)
                )
                .andExpect(
                        jsonPath("$.error").value("Bad Request")
                )
                .andExpect(
                        jsonPath("$.message").value("URL cannot be null or blank")
                )
                .andExpect(
                        jsonPath("$.path").value("/api/analyze")
                );

        verify(analyzeService).analyze(
                argThat(
                        analyzeRequest -> "  ".equals(analyzeRequest.getUrl())
                )
        );
    }

    @Test
    void shouldReturnInternalServerErrorWhenSslAnalysisFails() throws Exception {
        AnalyzeRequest request = new AnalyzeRequest("https://example.com");

        when(analyzeService.analyze(any(AnalyzeRequest.class))).thenThrow(
                new RuntimeException("Could not analyze SSL certificate")
        );

        mockMvc.perform(
                post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isInternalServerError())
                .andExpect(
                        jsonPath("$.status").value(500)
                )
                .andExpect(
                        jsonPath("$.error").value("Internal Server Error")
                )
                .andExpect(
                        jsonPath("$.message").value("Could not analyze SSL certificate")
                )
                .andExpect(
                        jsonPath("$.path").value("/api/analyze")
                );

        verify(analyzeService).analyze(
                argThat(
                        analyzeRequest -> "https://example.com".equals(analyzeRequest.getUrl())
                )
        );
    }

    @Test
    void shouldReturnErrorWhenJsonIsInvalid() throws Exception {
        String invalidJason = "{";

        mockMvc.perform(
                post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidJason)
                )
                .andExpect(status().isBadRequest())
                .andExpect(
                        jsonPath("$.status").value(400)
                )
                .andExpect(
                        jsonPath("$.error").value("Bad Request")
                )
                .andExpect(
                        jsonPath("$.message").value("Malformed JSON request")
                )
                .andExpect(
                        jsonPath("$.path").value("/api/analyze")
                );

        verifyNoInteractions(analyzeService);
    }

    @Test
    void shouldReturnBadRequestWhenRequestBodyIsMissing() throws Exception {
        mockMvc.perform(
                post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isBadRequest());

        verifyNoInteractions(analyzeService);
    }
}
