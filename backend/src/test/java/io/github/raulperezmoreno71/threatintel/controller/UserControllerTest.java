package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.config.SecurityConfig;
import io.github.raulperezmoreno71.threatintel.dto.ChangePasswordRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.LoginRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.RegisterRequest;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.EmailAlreadyExistException;
import io.github.raulperezmoreno71.threatintel.exception.InvalidCredentialException;
import io.github.raulperezmoreno71.threatintel.exception.UserNotFoundException;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.security.CustomAuthenticationEntryPoint;
import io.github.raulperezmoreno71.threatintel.security.JwtAuthenticationFilter;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
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
import org.springframework.test.util.ReflectionTestUtils;
import tools.jackson.databind.ObjectMapper;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@ImportAutoConfiguration({ServletWebSecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class})
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, CustomAuthenticationEntryPoint.class})
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void shouldRegisterUserSuccessfully() throws Exception {
        RegisterRequest request = new RegisterRequest("user@example.com", "prueba123");
        User user = new User("user@example.com", "encoded-password", UserStatus.ACTIVE);

        when(userService.register(any(RegisterRequest.class))).thenReturn(user);

        mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void shouldThrowEmailAlreadyExistExceptionWhenDuplicateEmail() throws Exception {
        RegisterRequest request = new RegisterRequest("user@example.com", "prueba123");

        when(userService.register(any(RegisterRequest.class))).thenThrow(new EmailAlreadyExistException("Email is already registered"));

        mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(request))
                )
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.message").value("Email is already registered"))
                .andExpect(jsonPath("$.path").value("/api/auth/register"));
    }

    @Test
    void shouldLoginUserSuccessfully() throws Exception {
        LoginRequest request = new LoginRequest("user@example.com", "prueba123");
        User user = new User("user@example.com", "encoded-password", UserStatus.ACTIVE);

        when(userService.login(any(LoginRequest.class))).thenReturn(user);
        when(jwtService.generateToken(user)).thenReturn("generated-jwt");

        mockMvc.perform(
                post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(cookie().value("access_token", "generated-jwt"))
                .andExpect(cookie().httpOnly("access_token", true))
                .andExpect(cookie().secure("access_token", false))
                .andExpect(cookie().path("access_token", "/"))
                .andExpect(cookie().sameSite("access_token", "Lax"));

        verify(userService).login(any(LoginRequest.class));
    }

    @Test
    void shouldReturnUnauthorizedWhenCredentialsAreInvalid() throws Exception {
        LoginRequest request = new LoginRequest("user@example.com", "prueba123");

        when(userService.login(any(LoginRequest.class))).thenThrow(new InvalidCredentialException("Invalid email or password"));

        mockMvc.perform(
                post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Invalid email or password"))
                .andExpect(jsonPath("$.path").value("/api/auth/login"));

        verify(userService).login(any(LoginRequest.class));
        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldReturnAuthenticatedUser() throws Exception {
        User user = new User("user@example.com", "encoded-password", UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "id", 1L);

        when(userService.getByEmail("user@example.com")).thenReturn(user);

        mockMvc.perform(
                get("/api/auth/me")
                        .with(user("user@example.com"))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        verify(userService).getByEmail("user@example.com");
    }

    @Test
    void shouldReturnAuthenticatedUserWhenJwtCookieIsValid() throws Exception {
        User user = new User(
                "user@example.com",
                "encoded-password",
                UserStatus.ACTIVE
        );
        ReflectionTestUtils.setField(user, "id", 1L);

        when(jwtService.extractEmail("valid-token"))
                .thenReturn("user@example.com");
        when(userService.getByEmail("user@example.com"))
                .thenReturn(user);

        mockMvc.perform(
                        get("/api/auth/me")
                                .cookie(new Cookie("access_token", "valid-token"))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        verify(jwtService).extractEmail("valid-token");
        verify(userService).getByEmail("user@example.com");
    }

    @Test
    void shouldReturnJsonUnauthorizedWhenJwtCookieIsInvalid() throws Exception {
        when(jwtService.extractEmail("invalid-token"))
                .thenThrow(new JwtException("Invalid token"));

        mockMvc.perform(
                        get("/api/auth/me")
                                .cookie(new Cookie("access_token", "invalid-token"))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication is required"))
                .andExpect(jsonPath("$.path").value("/api/auth/me"));

        verify(jwtService).extractEmail("invalid-token");
        verifyNoInteractions(userService);
    }

    @Test
    void shouldReturnUnauthorizedWhenUserIsNotAuthenticated() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication is required"))
                .andExpect(jsonPath("$.path").value("/api/auth/me"));

        verifyNoInteractions(userService);
    }

    @Test
    void shouldLogoutSuccessfully() throws Exception {
        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""))
                .andExpect(cookie().value("access_token", ""))
                .andExpect(cookie().maxAge("access_token", 0))
                .andExpect(cookie().httpOnly("access_token", true))
                .andExpect(cookie().secure("access_token", false))
                .andExpect(cookie().path("access_token", "/"))
                .andExpect(cookie().sameSite("access_token", "Lax"));
    }

    @Test
    void shouldChangePasswordSuccessfully() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "new-password"
        );

        mockMvc.perform(
                        post("/api/auth/change-password")
                                .with(user("user@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));

        verify(userService).changePassword(
                eq("user@example.com"),
                argThat(changePasswordRequest ->
                        "current-password".equals(changePasswordRequest.getCurrentPassword())
                                && "new-password".equals(changePasswordRequest.getNewPassword())
                )
        );
    }

    @Test
    void shouldReturnUnauthorizedWhenChangingPasswordWithoutAuthentication() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "new-password"
        );

        mockMvc.perform(
                        post("/api/auth/change-password")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Authentication is required"))
                .andExpect(jsonPath("$.path").value("/api/auth/change-password"));

        verifyNoInteractions(userService);
    }

    @Test
    void shouldReturnUnauthorizedWhenCurrentPasswordIsIncorrect() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest(
                "incorrect-password",
                "new-password"
        );

        doThrow(new InvalidCredentialException("Invalid password"))
                .when(userService)
                .changePassword(eq("user@example.com"), any(ChangePasswordRequest.class));

        mockMvc.perform(
                        post("/api/auth/change-password")
                                .with(user("user@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Invalid password"))
                .andExpect(jsonPath("$.path").value("/api/auth/change-password"));

        verify(userService).changePassword(
                eq("user@example.com"),
                any(ChangePasswordRequest.class)
        );
    }

    @Test
    void shouldReturnUnauthorizedWhenNewPasswordMatchesCurrentPassword() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "current-password"
        );

        doThrow(new InvalidCredentialException("New password must be different from current password"))
                .when(userService)
                .changePassword(eq("user@example.com"), any(ChangePasswordRequest.class));

        mockMvc.perform(
                        post("/api/auth/change-password")
                                .with(user("user@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("New password must be different from current password"))
                .andExpect(jsonPath("$.path").value("/api/auth/change-password"));

        verify(userService).changePassword(
                eq("user@example.com"),
                any(ChangePasswordRequest.class)
        );
    }

    @Test
    void shouldReturnNotFoundWhenChangingPasswordForUnknownUser() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest(
                "current-password",
                "new-password"
        );

        doThrow(new UserNotFoundException("User not found"))
                .when(userService)
                .changePassword(eq("missing@example.com"), any(ChangePasswordRequest.class));

        mockMvc.perform(
                        post("/api/auth/change-password")
                                .with(user("missing@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("User not found"))
                .andExpect(jsonPath("$.path").value("/api/auth/change-password"));

        verify(userService).changePassword(
                eq("missing@example.com"),
                any(ChangePasswordRequest.class)
        );
    }

    @Test
    void shouldReturnBadRequestWhenChangePasswordJsonIsMalformed() throws Exception {
        mockMvc.perform(
                        post("/api/auth/change-password")
                                .with(user("user@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{")
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Malformed JSON request"))
                .andExpect(jsonPath("$.path").value("/api/auth/change-password"));

        verifyNoInteractions(userService);
    }

    @Test
    void shouldReturnBadRequestWhenChangePasswordBodyIsMissing() throws Exception {
        mockMvc.perform(
                        post("/api/auth/change-password")
                                .with(user("user@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Malformed JSON request"))
                .andExpect(jsonPath("$.path").value("/api/auth/change-password"));

        verifyNoInteractions(userService);
    }
}
