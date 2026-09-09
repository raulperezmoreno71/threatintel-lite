package io.github.raulperezmoreno71.threatintel.security;

import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {
    private JwtService jwtService;
    private CustomAuthenticationEntryPoint authenticationEntryPoint;
    private JwtAuthenticationFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        authenticationEntryPoint = mock(CustomAuthenticationEntryPoint.class);
        filter = new JwtAuthenticationFilter(
                jwtService,
                authenticationEntryPoint
        );

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        filterChain = mock(FilterChain.class);

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/logout"
    })
    void shouldNotFilterPublicAuthenticationEndpoints(String path) {
        when(request.getServletPath()).thenReturn(path);

        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    void shouldFilterProtectedEndpoints() {
        when(request.getServletPath()).thenReturn("/api/analyze");

        assertFalse(filter.shouldNotFilter(request));
    }

    @Test
    void shouldContinueFilterChainWhenTokenIsMissing() throws Exception {
        when(request.getCookies()).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldIgnoreCookiesWithDifferentNames() throws Exception {
        Cookie cookie = new Cookie("session_id", "session-value");

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldAuthenticateUserWhenTokenIsValid() throws Exception {
        Cookie cookie = new Cookie("access_token", "valid-token");

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(jwtService.extractEmail("valid-token")).thenReturn("user@example.com");

        filter.doFilterInternal(request, response, filterChain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals("user@example.com", authentication.getName());
        assertTrue(authentication.isAuthenticated());

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldFindAccessTokenAmongMultipleCookies() throws Exception {
        Cookie preferencesCookie = new Cookie("preferences", "dark-mode");
        Cookie accessTokenCookie = new Cookie("access_token", "valid-token");
        Cookie sessionCookie = new Cookie("session_id", "session-value");

        when(request.getCookies()).thenReturn(new Cookie[]{
                preferencesCookie,
                accessTokenCookie,
                sessionCookie
        });
        when(jwtService.extractEmail("valid-token"))
                .thenReturn("user@example.com");

        filter.doFilterInternal(request, response, filterChain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals("user@example.com", authentication.getName());

        verify(jwtService).extractEmail("valid-token");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotReplaceExistingAuthentication() throws Exception {
        Cookie cookie = new Cookie("access_token", "valid-token");
        Authentication existingAuthentication =
                new UsernamePasswordAuthenticationToken(
                        "existing@example.com",
                        null,
                        Collections.emptyList()
                );

        SecurityContextHolder.getContext()
                .setAuthentication(existingAuthentication);

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(jwtService.extractEmail("valid-token"))
                .thenReturn("different@example.com");

        filter.doFilterInternal(request, response, filterChain);

        assertSame(
                existingAuthentication,
                SecurityContextHolder.getContext().getAuthentication()
        );

        verify(jwtService).extractEmail("valid-token");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldContinueWithoutAuthenticationWhenTokenHasNoEmail() throws Exception {
        Cookie cookie = new Cookie("access_token", "token-without-email");

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(jwtService.extractEmail("token-without-email"))
                .thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(jwtService).extractEmail("token-without-email");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldReturnUnauthorizedWhenTokenIsInvalid() throws Exception {
        Cookie cookie = new Cookie("access_token", "invalid-token");
        JwtException cause = new JwtException("Invalid token");
        Authentication existingAuthentication =
                new UsernamePasswordAuthenticationToken(
                        "existing@example.com",
                        null,
                        Collections.emptyList()
                );

        SecurityContextHolder.getContext()
                .setAuthentication(existingAuthentication);
        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(jwtService.extractEmail("invalid-token")).thenThrow(cause);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationEntryPoint).commence(
                eq(request),
                eq(response),
                argThat(exception ->
                        exception.getMessage().equals("Invalid token")
                                && exception.getCause() == cause
                )
        );
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void shouldReturnUnauthorizedWhenTokenIsIllegal() throws Exception {
        Cookie cookie = new Cookie("access_token", "illegal-token");
        IllegalArgumentException cause =
                new IllegalArgumentException("Token is malformed");

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(jwtService.extractEmail("illegal-token"))
                .thenThrow(cause);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(authenticationEntryPoint).commence(
                eq(request),
                eq(response),
                argThat(exception ->
                        exception.getMessage().equals("Invalid token")
                                && exception.getCause() == cause
                )
        );
        verify(filterChain, never()).doFilter(request, response);
    }
}
