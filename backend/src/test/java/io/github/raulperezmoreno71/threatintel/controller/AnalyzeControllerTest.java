package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.config.SecurityConfig;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.security.CustomAuthenticationEntryPoint;
import io.github.raulperezmoreno71.threatintel.security.JwtAuthenticationFilter;
import io.github.raulperezmoreno71.threatintel.service.AnalyzeService;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AnalyzeController.class)
@ImportAutoConfiguration({ServletWebSecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class})
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, CustomAuthenticationEntryPoint.class})
class AnalyzeControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AnalyzeService analyzeService;

    @MockitoBean
    private JwtService jwtService;

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

        when(analyzeService.analyze(any(AnalyzeRequest.class)))
                .thenReturn(serviceResponse);

        mockMvc.perform(
                        post("/api/analyze")
                                .with(user("test@example.com"))
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
                        analyzeRequest ->
                                "https://example.com".equals(analyzeRequest.getUrl())
                )
        );
    }

    @Test
    void shouldReturnBadRequestWhenUrlIsInvalid() throws Exception {
        AnalyzeRequest request = new AnalyzeRequest("  ");

        when(analyzeService.analyze(any(AnalyzeRequest.class)))
                .thenThrow(
                        new IllegalArgumentException(
                                "URL cannot be null or blank"
                        )
                );

        mockMvc.perform(
                        post("/api/analyze")
                                .with(user("test@example.com"))
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

        when(analyzeService.analyze(any(AnalyzeRequest.class)))
                .thenThrow(
                        new RuntimeException(
                                "Could not analyze SSL certificate"
                        )
                );

        mockMvc.perform(
                        post("/api/analyze")
                                .with(user("test@example.com"))
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
                        jsonPath("$.message")
                                .value("Could not analyze SSL certificate")
                )
                .andExpect(
                        jsonPath("$.path").value("/api/analyze")
                );

        verify(analyzeService).analyze(
                argThat(
                        analyzeRequest ->
                                "https://example.com".equals(analyzeRequest.getUrl())
                )
        );
    }

    @Test
    void shouldReturnErrorWhenJsonIsInvalid() throws Exception {
        String invalidJason = "{";

        mockMvc.perform(
                        post("/api/analyze")
                                .with(user("test@example.com"))
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
                                .with(user("test@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isBadRequest());

        verifyNoInteractions(analyzeService);
    }

    @Test
    void shouldReturnUnauthorizedWhenUserIsNotAuthenticated() throws Exception {
        AnalyzeRequest request = new AnalyzeRequest("https://example.com");

        mockMvc.perform(
                        post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication is required"))
                .andExpect(jsonPath("$.path").value("/api/analyze"));

        verifyNoInteractions(analyzeService);
    }

    @Test
    void shouldAllowPreflightRequestFromConfiguredFrontendOrigin() throws Exception {
        mockMvc.perform(
                        options("/api/analyze")
                                .header(HttpHeaders.ORIGIN, "http://localhost:5173")
                                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type")
                )
                .andExpect(status().isOk())
                .andExpect(header().string(
                        HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                        "http://localhost:5173"
                ))
                .andExpect(header().string(
                        HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                        "GET,POST,DELETE,OPTIONS"
                ))
                .andExpect(header().string(
                        HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
                        "true"
                ));

        verifyNoInteractions(analyzeService);
    }

    @Test
    void shouldRejectPreflightRequestFromUnknownOrigin() throws Exception {
        mockMvc.perform(
                        options("/api/analyze")
                                .header(HttpHeaders.ORIGIN, "https://unknown.example")
                                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                )
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));

        verifyNoInteractions(analyzeService);
    }
}
