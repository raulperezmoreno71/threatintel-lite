package io.github.raulperezmoreno71.threatintel.exception;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
        assertErrorResponse(
                "/test/errors/runtime",
                500,
                "Internal Server Error",
                "Unexpected failure"
        );
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
                .andExpect(jsonPath("$.status").value(expectedStatus))
                .andExpect(jsonPath("$.error").value(expectedError))
                .andExpect(jsonPath("$.message").value(expectedMessage))
                .andExpect(jsonPath("$.path").value(path));
    }

    @RestController
    @RequestMapping("/test/errors")
    static class ThrowingController {

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

        @PostMapping("/malformed-json")
        void malformedJson(@RequestBody AnalyzeRequest request) {
        }
    }
}
