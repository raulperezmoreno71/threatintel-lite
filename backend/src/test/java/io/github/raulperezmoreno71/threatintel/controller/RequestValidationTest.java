package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.config.SecurityConfig;
import io.github.raulperezmoreno71.threatintel.dto.auth.LoginRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.RegisterRequest;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.security.CustomAuthenticationEntryPoint;
import io.github.raulperezmoreno71.threatintel.security.JwtAuthenticationFilter;
import io.github.raulperezmoreno71.threatintel.service.AnalysisRateLimitService;
import io.github.raulperezmoreno71.threatintel.service.AnalyzeService;
import io.github.raulperezmoreno71.threatintel.service.PendingAnalysisStore;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import io.github.raulperezmoreno71.threatintel.service.LoginRateLimitService;
import org.junit.jupiter.api.BeforeEach;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
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

import java.util.Map;
import java.util.stream.Stream;

import static io.github.raulperezmoreno71.threatintel.support.CsrfRequestPostProcessors.csrfCookieAndHeader;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest({UserController.class, AnalyzeController.class})
@ImportAutoConfiguration({ServletWebSecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class})
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, CustomAuthenticationEntryPoint.class})
class RequestValidationTest {
    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @MockitoBean private UserService userService;
    @MockitoBean private JwtService jwtService;
    @MockitoBean private UserRepository userRepository;
    @MockitoBean private AnalyzeService analyzeService;
    @MockitoBean private PendingAnalysisStore pendingAnalysisStore;
    @MockitoBean private AnalysisRateLimitService rateLimitService;
    @MockitoBean private LoginRateLimitService loginRateLimitService;

    @BeforeEach
    void allowLoginAttempts() {
        when(loginRateLimitService.acquire(any())).thenReturn(mock(LoginRateLimitService.Attempt.class));
    }

    static Stream<Arguments> invalidRequests() {
        return Stream.of(
                Arguments.of("/api/auth/register", Map.of(), "email"),
                Arguments.of("/api/auth/register", Map.of("email", " ", "password", "password123"), "email"),
                Arguments.of("/api/auth/register", Map.of("email", "invalid-email", "password", "password123"), "email"),
                Arguments.of("/api/auth/register", Map.of("email", "a".repeat(244) + "@example.com", "password", "password123"), "email"),
                Arguments.of("/api/auth/register", Map.of("email", "user@example.com", "password", "short"), "password"),
                Arguments.of("/api/auth/register", Map.of("email", "user@example.com", "password", " ".repeat(8)), "password"),
                Arguments.of("/api/auth/register", Map.of("email", "user@example.com", "password", "x".repeat(65)), "password"),
                Arguments.of("/api/auth/login", Map.of("email", "user@example.com"), "password"),
                Arguments.of("/api/auth/login", Map.of("email", "bad-email", "password", "password123"), "email"),
                Arguments.of("/api/auth/change-password", Map.of("newPassword", "password123"), "currentPassword"),
                Arguments.of("/api/auth/change-password", Map.of("currentPassword", "old-password", "newPassword", "short"), "newPassword"),
                Arguments.of("/api/auth/change-password", Map.of("currentPassword", "old-password", "newPassword", "x".repeat(65)), "newPassword"),
                Arguments.of("/api/analyze", Map.of(), "url"),
                Arguments.of("/api/analyze", Map.of("url", " "), "url"),
                Arguments.of("/api/analyze", Map.of("url", "https://example.com/" + "x".repeat(2048)), "url")
        );
    }

    @ParameterizedTest
    @MethodSource("invalidRequests")
    void rejectsInvalidInputBeforeCallingServices(String endpoint, Map<String, String> body, String field) throws Exception {
        mockMvc.perform(post(endpoint)
                        .with(user("user@example.com"))
                        .with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.path").value(endpoint))
                .andExpect(jsonPath("$.message", containsString(field)))
                .andExpect(content().string(not(containsString("password123"))))
                .andExpect(content().string(not(containsString("old-password"))));

        verifyNoInteractions(userService, analyzeService, pendingAnalysisStore, rateLimitService, jwtService, loginRateLimitService);
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 64})
    void acceptsNewPasswordsAtBothLengthBoundaries(int length) throws Exception {
        when(userService.register(any(RegisterRequest.class)))
                .thenReturn(new User("user@example.com", "encoded", UserStatus.ACTIVE));

        mockMvc.perform(post("/api/auth/register")
                        .with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "user@example.com", "password", "x".repeat(length)))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("user@example.com"));
    }

    @Test
    void allowsExistingShortPasswordsToReachAuthentication() throws Exception {
        when(userService.login(any(LoginRequest.class)))
                .thenReturn(new User("user@example.com", "encoded", UserStatus.ACTIVE));
        when(jwtService.generateToken(any(User.class))).thenReturn("signed-token");

        mockMvc.perform(post("/api/auth/login")
                        .with(csrfCookieAndHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.com\",\"password\":\"short\"}"))
                .andExpect(status().isOk())
                .andExpect(cookie().value("access_token", "signed-token"));
    }
}
