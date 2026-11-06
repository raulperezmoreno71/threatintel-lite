package io.github.raulperezmoreno71.threatintel.exception;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import jakarta.validation.Valid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

import java.util.UUID;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

class GlobalExceptionHandlerTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = standaloneSetup(new ThrowingController())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void shouldReturnGatewayTimeoutWhenAnalysisBudgetExpires() throws Exception {
        assertErrorResponse("/test/errors/analysis-timeout", 504, "Gateway Timeout", "Analysis time limit exceeded");
    }

    @Test
    void shouldReturnServiceUnavailableWhenDnsWorkersAreBusy() throws Exception {
        assertErrorResponse("/test/errors/dns-busy", 503, "Service Unavailable", "DNS resolver is busy; try again later");
    }

    @Test
    void shouldReturnNotFoundWhenAnalysisDoesNotExist() throws Exception {
        assertErrorResponse(
                "/test/errors/analysis-not-found",
                404,
                "Not Found",
                "Analysis not found with id: 42"
        );
    }

    @Test
    void shouldReturnNotFoundWhenUserDoesNotExist() throws Exception {
        assertErrorResponse(
                "/test/errors/user-not-found",
                404,
                "Not Found",
                "User not found"
        );
    }

    @Test
    void shouldReturnBadRequestForIllegalArgument() throws Exception {
        assertErrorResponse(
                "/test/errors/illegal-argument",
                400,
                "Bad Request",
                "Invalid argument"
        );
    }

    @Test
    void shouldReturnConflictWhenEmailAlreadyExists() throws Exception {
        assertErrorResponse(
                "/test/errors/email-already-exists",
                409,
                "Conflict",
                "Email already exists"
        );
    }

    @Test
    void shouldReturnUnauthorizedForInvalidCredentials() throws Exception {
        assertErrorResponse(
                "/test/errors/invalid-credentials",
                401,
                "Unauthorized",
                "Invalid credentials"
        );
    }

    @Test
    void shouldReturnInternalServerErrorForUnexpectedRuntimeException() throws Exception {
        MvcResult result = mockMvc.perform(get("/test/errors/sensitive-runtime"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.error").value("Internal Server Error"))
                .andExpect(jsonPath("$.path").value("/test/errors/sensitive-runtime"))
                .andExpect(jsonPath("$", aMapWithSize(4)))
                .andReturn();

        String incidentId = assertIncidentReference(result);
        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains("Unexpected failure"));
        assertFalse(body.contains("SELECT"));
        assertFalse(body.contains("private_users"));
        assertFalse(body.contains("dummy-secret"));
        assertFalse(body.contains("dummy-cause"));
        assertEquals(4, UUID.fromString(incidentId).version());
    }

    @Test
    void shouldGenerateFreshIncidentIdsRegardlessOfClientSuppliedIds() throws Exception {
        String clientId = "63e053a5-6ad8-4ab4-b8b8-5fa69998da5c";
        MvcResult first = mockMvc.perform(get("/test/errors/runtime")
                        .header("X-Error-ID", clientId)
                        .header("X-Request-ID", clientId)
                        .header("X-Correlation-ID", clientId))
                .andExpect(status().isInternalServerError())
                .andReturn();
        MvcResult second = mockMvc.perform(get("/test/errors/runtime"))
                .andExpect(status().isInternalServerError())
                .andReturn();

        String firstId = assertIncidentReference(first);
        String secondId = assertIncidentReference(second);
        assertNotEquals(clientId, firstId);
        assertNotEquals(firstId, secondId);
    }

    @Test
    void shouldLogIncidentIdAndOriginalThrowableWithoutRequestData() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            MvcResult result = mockMvc.perform(get("/test/errors/runtime")
                            .queryParam("target", "https://dummy.invalid/private-query")
                            .header("Authorization", "Bearer dummy-jwt")
                            .header("Cookie", "session=dummy-cookie")
                            .content("{\"password\":\"dummy-password\"}"))
                    .andExpect(status().isInternalServerError())
                    .andReturn();
            String incidentId = assertIncidentReference(result);

            assertEquals(1, appender.list.size());
            ILoggingEvent event = appender.list.getFirst();
            assertEquals(Level.ERROR, event.getLevel());
            assertTrue(event.getFormattedMessage().contains(incidentId));
            ThrowableProxy throwable = assertInstanceOf(ThrowableProxy.class, event.getThrowableProxy());
            assertSame(result.getResolvedException(), throwable.getThrowable());
            assertTrue(throwable.getStackTraceElementProxyArray().length > 0);
            for (String requestData : new String[]{"private-query", "dummy-jwt", "dummy-cookie", "dummy-password", "/test/errors/runtime"}) {
                assertFalse(event.getFormattedMessage().contains(requestData));
            }
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    @Test
    void shouldPreserveLoginRateLimitMessageAndRetryAfter() throws Exception {
        mockMvc.perform(get("/test/errors/login-rate-limit"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "123"))
                .andExpect(header().doesNotExist("X-Error-ID"))
                .andExpect(jsonPath("$.message").value("Too many login attempts. Please try again later."));
    }

    @Test
    void shouldPreserveAnalysisRateLimitMessage() throws Exception {
        assertErrorResponse("/test/errors/analysis-rate-limit", 429, "Too Many Requests",
                "Too many analysis request. Please try again later.");
    }

    @Test
    void shouldPreserveActionableJakartaValidationMessage() throws Exception {
        mockMvc.perform(post("/test/errors/malformed-json")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\" \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("X-Error-ID"))
                .andExpect(jsonPath("$.message").value("url: URL cannot be null or blank"));
    }

    @Test
    void shouldReturnBadRequestWhenJsonIsMalformed() throws Exception {
        String path = "/test/errors/malformed-json";

        mockMvc.perform(
                        post(path)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{")
                )
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("X-Error-ID"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Malformed JSON request"))
                .andExpect(jsonPath("$.path").value(path));
    }

    private void assertErrorResponse(
            String path,
            int expectedStatus,
            String expectedError,
            String expectedMessage
    ) throws Exception {
        mockMvc.perform(get(path))
                .andExpect(status().is(expectedStatus))
                .andExpect(header().doesNotExist("X-Error-ID"))
                .andExpect(jsonPath("$.status").value(expectedStatus))
                .andExpect(jsonPath("$.error").value(expectedError))
                .andExpect(jsonPath("$.message").value(expectedMessage))
                .andExpect(jsonPath("$.path").value(path));
    }

    private String assertIncidentReference(MvcResult result) throws Exception {
        String incidentId = result.getResponse().getHeader("X-Error-ID");
        assertNotNull(incidentId);
        assertEquals(incidentId, UUID.fromString(incidentId).toString());
        String message = new ObjectMapper().readTree(result.getResponse().getContentAsString())
                .get("message").asString();
        assertEquals("An unexpected error occurred. Please try again later. Reference: " + incidentId, message);
        return incidentId;
    }

    @RestController
    @RequestMapping("/test/errors")
    static class ThrowingController {

        @GetMapping("/analysis-timeout")
        void analysisTimeout() {
            throw new AnalysisTimeoutException();
        }

        @GetMapping("/dns-busy")
        void dnsBusy() {
            throw new DnsResolverBusyException();
        }

        @GetMapping("/analysis-not-found")
        void analysisNotFound() {
            throw new AnalysisNotFoundException(42L);
        }

        @GetMapping("/user-not-found")
        void userNotFound() {
            throw new UserNotFoundException("User not found");
        }

        @GetMapping("/illegal-argument")
        void illegalArgument() {
            throw new IllegalArgumentException("Invalid argument");
        }

        @GetMapping("/email-already-exists")
        void emailAlreadyExists() {
            throw new EmailAlreadyExistException("Email already exists");
        }

        @GetMapping("/invalid-credentials")
        void invalidCredentials() {
            throw new InvalidCredentialException("Invalid credentials");
        }

        @GetMapping("/runtime")
        void runtimeException() {
            throw new RuntimeException("Unexpected failure");
        }

        @GetMapping("/sensitive-runtime")
        void sensitiveRuntimeException() {
            throw new RuntimeException("Unexpected failure: SELECT password FROM private_users; token=dummy-secret",
                    new IllegalStateException("dummy-cause"));
        }

        @GetMapping("/login-rate-limit")
        void loginRateLimit() {
            throw new LoginRateLimitExceededException(123);
        }

        @GetMapping("/analysis-rate-limit")
        void analysisRateLimit() {
            throw new AnalysisRateLimitExceededException();
        }

        @PostMapping("/malformed-json")
        void malformedJson(@Valid @RequestBody AnalyzeRequest request) {
        }
    }
}
