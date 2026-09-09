package io.github.raulperezmoreno71.threatintel.config;

import io.github.raulperezmoreno71.threatintel.security.CustomAuthenticationEntryPoint;
import io.github.raulperezmoreno71.threatintel.security.JwtAuthenticationFilter;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecurityConfigTest.SecurityTestController.class)
@ImportAutoConfiguration({ServletWebSecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class})
@Import({
        SecurityConfig.class,
        JwtAuthenticationFilter.class,
        CustomAuthenticationEntryPoint.class,
        SecurityConfigTest.SecurityTestController.class
})
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CorsConfigurationSource corsConfigurationSource;

    @MockitoBean
    private JwtService jwtService;

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/logout"
    })
    void shouldAllowAuthenticationEndpointsWithoutAuthentication(String path) throws Exception {
        mockMvc.perform(post(path))
                .andExpect(status().isOk())
                .andExpect(content().string("ok"));

        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldRejectAnonymousRequestToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/test/protected"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message").value("Authentication is required"));

        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldAllowAuthenticatedRequestToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/test/protected").with(user("test@example.com")))
                .andExpect(status().isOk())
                .andExpect(content().string("protected"));

        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldProvideAWorkingPasswordEncoder() {
        String rawPassword = "correct-horse-battery-staple";

        String encodedPassword = passwordEncoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(passwordEncoder.matches(rawPassword, encodedPassword));
        assertFalse(passwordEncoder.matches("wrong-password", encodedPassword));
    }

    @Test
    void shouldExposeExpectedCorsConfiguration() {
        HttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest(
                "OPTIONS",
                "/api/analyze"
        );

        CorsConfiguration configuration = corsConfigurationSource.getCorsConfiguration(request);

        assertNotNull(configuration);
        assertEquals(List.of("http://localhost:5173"), configuration.getAllowedOrigins());
        assertEquals(List.of("GET", "POST", "DELETE", "OPTIONS"), configuration.getAllowedMethods());
        assertEquals(List.of("Authorization", "Content-Type"), configuration.getAllowedHeaders());
        assertEquals(Boolean.TRUE, configuration.getAllowCredentials());
        assertEquals("http://localhost:5173", configuration.checkOrigin("http://localhost:5173"));
        assertNull(configuration.checkOrigin("https://unknown.example"));
        assertEquals(
                List.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE, HttpMethod.OPTIONS),
                configuration.checkHttpMethod(HttpMethod.POST)
        );
        assertNull(configuration.checkHttpMethod(HttpMethod.PUT));
    }

    @RestController
    static class SecurityTestController {

        @PostMapping({
                "/api/auth/register",
                "/api/auth/login",
                "/api/auth/logout"
        })
        String publicEndpoint() {
            return "ok";
        }

        @GetMapping("/test/protected")
        String protectedEndpoint() {
            return "protected";
        }
    }
}
