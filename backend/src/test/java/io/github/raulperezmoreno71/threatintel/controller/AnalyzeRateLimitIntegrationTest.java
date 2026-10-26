package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.GlobalExceptionHandler;
import io.github.raulperezmoreno71.threatintel.service.AnalysisRateLimitService;
import io.github.raulperezmoreno71.threatintel.service.AnalyzeService;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Clock;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

// Real controller, rate limiter and advice; database and outbound analysis are isolated.
// Security filters are covered separately by AnalyzeControllerTest.
class AnalyzeRateLimitIntegrationTest {

    private static final Instant START = Instant.parse("2026-01-01T12:00:00Z");

    private MockMvc mockMvc;
    private AnalyzeService analyzeService;
    private Clock clock;

    @BeforeEach
    void setUp() {
        clock = mock(Clock.class);
        when(clock.instant()).thenReturn(START);
        AnalysisRateLimitService limiter = new AnalysisRateLimitService(5, 60, clock);

        UserService userService = mock(UserService.class);
        User firstUser = mock(User.class);
        when(firstUser.getId()).thenReturn(1L);
        when(userService.getByEmail("first@example.com")).thenReturn(firstUser);
        User secondUser = mock(User.class);
        when(secondUser.getId()).thenReturn(2L);
        when(userService.getByEmail("second@example.com")).thenReturn(secondUser);

        analyzeService = mock(AnalyzeService.class);
        when(analyzeService.analyze(any(AnalyzeRequest.class))).thenReturn(
                new AnalyzeResponse("URL analyzed successfully", "https://example.com",
                        "example.com", null, null, null, null, null));

        mockMvc = standaloneSetup(new AnalyzeController(analyzeService, limiter, userService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void shouldRejectSixthRequestAndRecoverWhenWindowExpires() throws Exception {
        for (int i = 0; i < 5; i++) {
            analyzeAs("first@example.com").andExpect(status().isOk());
        }

        analyzeAs("first@example.com")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"))
                .andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(jsonPath("$.path").value("/api/analyze"));

        when(clock.instant()).thenReturn(START.plusSeconds(60).minusNanos(1));
        analyzeAs("first@example.com").andExpect(status().isTooManyRequests());
        verify(analyzeService, times(5)).analyze(any(AnalyzeRequest.class));

        when(clock.instant()).thenReturn(START.plusSeconds(60));
        analyzeAs("first@example.com").andExpect(status().isOk());
        verify(analyzeService, times(6)).analyze(any(AnalyzeRequest.class));
    }

    @Test
    void shouldGiveEachAuthenticatedUserAnIndependentLimit() throws Exception {
        for (int i = 0; i < 5; i++) {
            analyzeAs("first@example.com").andExpect(status().isOk());
        }
        analyzeAs("first@example.com").andExpect(status().isTooManyRequests());

        for (int i = 0; i < 5; i++) {
            analyzeAs("second@example.com").andExpect(status().isOk());
        }
        analyzeAs("second@example.com").andExpect(status().isTooManyRequests());

        verify(analyzeService, times(10)).analyze(any(AnalyzeRequest.class));
    }

    @Test
    void shouldCountAdmittedRequestsEvenWhenAnalysisFails() throws Exception {
        when(analyzeService.analyze(any(AnalyzeRequest.class)))
                .thenThrow(new RuntimeException("Analysis failed"));

        for (int i = 0; i < 5; i++) {
            analyzeAs("first@example.com").andExpect(status().isInternalServerError());
        }
        analyzeAs("first@example.com").andExpect(status().isTooManyRequests());

        verify(analyzeService, times(5)).analyze(any(AnalyzeRequest.class));
    }

    private ResultActions analyzeAs(String email) throws Exception {
        return mockMvc.perform(post("/api/analyze")
                .principal(() -> email)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"));
    }
}
