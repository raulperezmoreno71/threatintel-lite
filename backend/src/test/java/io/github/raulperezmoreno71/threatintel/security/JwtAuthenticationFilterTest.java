package io.github.raulperezmoreno71.threatintel.security;

import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {
    private JwtService jwtService;
    private UserRepository userRepository;
    private CustomAuthenticationEntryPoint authenticationEntryPoint;
    private JwtAuthenticationFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        jwtService = mock(JwtService.class);
        userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(new User("user@example.com", "hash", UserStatus.ACTIVE)));
        authenticationEntryPoint = mock(CustomAuthenticationEntryPoint.class);
        filter = new JwtAuthenticationFilter(
                jwtService,
                authenticationEntryPoint,
                userRepository
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
            "/api/auth/logout",
            "/api/health"
    })
    void shouldNotFilterPublicEndpoints(String path) {
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
        when(jwtService.parseToken("valid-token")).thenReturn(new JwtService.TokenIdentity("user@example.com", 0));

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
        when(jwtService.parseToken("valid-token"))
                .thenReturn(new JwtService.TokenIdentity("user@example.com", 0));

        filter.doFilterInternal(request, response, filterChain);

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        assertNotNull(authentication);
        assertEquals("user@example.com", authentication.getName());

        verify(jwtService).parseToken("valid-token");
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
        when(jwtService.parseToken("valid-token"))
                .thenReturn(new JwtService.TokenIdentity("different@example.com", 0));
        when(userRepository.findByEmail("different@example.com"))
                .thenReturn(Optional.of(new User("different@example.com", "hash", UserStatus.ACTIVE)));

        filter.doFilterInternal(request, response, filterChain);

        assertSame(
                existingAuthentication,
                SecurityContextHolder.getContext().getAuthentication()
        );

        verify(jwtService).parseToken("valid-token");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectTokenWithoutEmailBeforeDatabaseLookup() throws Exception {
        Cookie cookie = new Cookie("access_token", "token-without-email");

        when(request.getCookies()).thenReturn(new Cookie[]{cookie});
        when(jwtService.parseToken("token-without-email"))
                .thenThrow(new JwtException("Token subject is required"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());

        verify(jwtService).parseToken("token-without-email");
        verify(authenticationEntryPoint).commence(eq(request), eq(response), any(BadCredentialsException.class));
        verifyNoInteractions(userRepository, filterChain);
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
        when(jwtService.parseToken("invalid-token")).thenThrow(cause);

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
        when(jwtService.parseToken("illegal-token"))
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

    @ParameterizedTest
    @ValueSource(longs = {0L, 2L})
    void shouldRejectBothOlderAndNewerVersionsAndClearExistingAuthentication(long tokenVersion) throws Exception {
        User user = new User("user@example.com", "hash", UserStatus.ACTIVE);
        user.incrementSessionVersion();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("access_token", "versioned-token")});
        when(jwtService.parseToken("versioned-token"))
                .thenReturn(new JwtService.TokenIdentity("user@example.com", tokenVersion));
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                "existing@example.com", null, Collections.emptyList()));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(authenticationEntryPoint).commence(eq(request), eq(response), any(BadCredentialsException.class));
        verifyNoInteractions(filterChain);
    }
}
