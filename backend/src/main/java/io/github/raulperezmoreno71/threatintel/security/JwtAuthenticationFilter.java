package io.github.raulperezmoreno71.threatintel.security;

import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtService jwtService, CustomAuthenticationEntryPoint authenticationEntryPoint, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.userRepository = userRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        return path.equals("/api/auth/login") || path.equals("/api/auth/register") || path.equals("/api/auth/logout") || path.equals("/api/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractTokenFromCookies(request);

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            var identity = jwtService.parseToken(token);
            var user = userRepository.findByEmail(identity.email())
                    .orElseThrow(() -> new BadCredentialsException("Invalid session"));

            if (user.getStatus() != UserStatus.ACTIVE || user.getSessionVersion() != identity.sessionVersion()) {
                throw new BadCredentialsException("Invalid session");
            }

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(identity.email(), null, Collections.emptyList());

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (JwtException | IllegalArgumentException | BadCredentialsException exception) {
            SecurityContextHolder.clearContext();

            authenticationEntryPoint.commence(request, response, new BadCredentialsException("Invalid token", exception));
            return;
        } catch (DataAccessException databaseFailure) {
            SecurityContextHolder.clearContext();
            throw databaseFailure;
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromCookies(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if ("access_token".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }
}
