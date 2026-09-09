package io.github.raulperezmoreno71.threatintel.security;

import io.github.raulperezmoreno71.threatintel.dto.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import tools.jackson.databind.json.JsonMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CustomAuthenticationEntryPointTest {

    private JsonMapper jsonMapper;
    private CustomAuthenticationEntryPoint authenticationEntryPoint;

    @BeforeEach
    void setUp() {
        jsonMapper = JsonMapper.builder().build();
        authenticationEntryPoint = new CustomAuthenticationEntryPoint(jsonMapper);
    }

    @Test
    void shouldWriteStandardUnauthorizedJsonResponse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/analyses");
        MockHttpServletResponse response = new MockHttpServletResponse();

        authenticationEntryPoint.commence(
                request,
                response,
                new BadCredentialsException("Invalid token")
        );

        ErrorResponse errorResponse = jsonMapper.readValue(
                response.getContentAsByteArray(),
                ErrorResponse.class
        );

        assertEquals(401, response.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
        assertEquals(401, errorResponse.getStatus());
        assertEquals("Unauthorized", errorResponse.getError());
        assertEquals("Authentication is required", errorResponse.getMessage());
        assertEquals("/api/analyses", errorResponse.getPath());
    }
}
