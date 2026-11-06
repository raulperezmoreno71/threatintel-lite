package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.ChangePasswordRequest;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.InvalidCredentialException;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import static io.github.raulperezmoreno71.threatintel.support.CsrfRequestPostProcessors.csrfCookieAndHeader;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class PasswordChangeIntegrationTest {
    @Container
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16")
            .withDatabaseName("password_change_test").withUsername("test").withPassword("test");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("jwt.secret", () -> "7bqCs1rsC+PvKz2VJ6EWI8PGqLoLTmHuK6RE3zsKSDU=");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserService userService;
    @Autowired private UserRepository users;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactions;
    @MockitoSpyBean private PasswordEncoder encoder;
    @MockitoSpyBean private JwtService jwtService;
    private User user;

    @BeforeEach
    void createAccount() {
        user = users.saveAndFlush(new User("password-" + UUID.randomUUID() + "@example.com",
                encoder.encode("current-password"), UserStatus.ACTIVE));
    }

    @Test
    void changesPasswordRevokesOldTokensAndKeepsCurrentBrowserAuthenticated() throws Exception {
        Cookie oldCookie = new Cookie("access_token", jwtService.generateToken(user));
        var result = changePassword(oldCookie, "current-password", "new-password")
                .andExpect(status().isNoContent())
                .andExpect(content().string(""))
                .andExpect(cookie().httpOnly("access_token", true))
                .andExpect(cookie().secure("access_token", false))
                .andExpect(cookie().path("access_token", "/"))
                .andExpect(cookie().sameSite("access_token", "Lax"))
                .andReturn();

        Cookie renewedCookie = result.getResponse().getCookie("access_token");
        assertNotNull(renewedCookie);
        assertNotEquals(oldCookie.getValue(), renewedCookie.getValue());
        assertEquals(1L, jwtService.parseToken(renewedCookie.getValue()).sessionVersion());
        User stored = users.findByEmail(user.getEmail()).orElseThrow();
        assertEquals(1L, stored.getSessionVersion());
        assertTrue(encoder.matches("new-password", stored.getPasswordHash()));

        mockMvc.perform(get("/api/auth/me").cookie(oldCookie)).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/auth/me").cookie(renewedCookie))
                .andExpect(status().isOk()).andExpect(jsonPath("$.email").value(user.getEmail()));
        login("current-password").andExpect(status().isUnauthorized());
        login("new-password").andExpect(status().isOk());
    }

    @ParameterizedTest
    @CsvSource({"incorrect-password,new-password", "current-password,current-password"})
    void rejectedChangesPreservePasswordVersionAndExistingSession(String current, String next) throws Exception {
        Cookie cookie = new Cookie("access_token", jwtService.generateToken(user));
        clearInvocations(jwtService);
        changePassword(cookie, current, next).andExpect(status().isUnauthorized())
                .andExpect(cookie().doesNotExist("access_token"));
        User stored = users.findByEmail(user.getEmail()).orElseThrow();
        assertEquals(0L, stored.getSessionVersion());
        assertEquals(user.getPasswordHash(), stored.getPasswordHash());
        verify(jwtService, never()).generateToken(any(User.class));
        mockMvc.perform(get("/api/auth/me").cookie(cookie)).andExpect(status().isOk());
    }

    @Test
    void persistenceFailureRollsBackBothValuesAndDoesNotIssueANewToken() throws Exception {
        Cookie cookie = new Cookie("access_token", jwtService.generateToken(user));
        clearInvocations(jwtService);
        // Exceed the real PostgreSQL column limit to fail at transaction persistence/commit.
        doReturn("x".repeat(300)).when(encoder).encode("new-password");
        changePassword(cookie, "current-password", "new-password")
                .andExpect(status().isInternalServerError()).andExpect(cookie().doesNotExist("access_token"));
        User stored = users.findByEmail(user.getEmail()).orElseThrow();
        assertEquals(0L, stored.getSessionVersion());
        assertEquals(user.getPasswordHash(), stored.getPasswordHash());
        verify(jwtService, never()).generateToken(any(User.class));
        mockMvc.perform(get("/api/auth/me").cookie(cookie)).andExpect(status().isOk());
    }

    @Test
    void eachSuccessfulChangeIncrementsThePersistedVersion() {
        userService.changePassword(user.getEmail(), new ChangePasswordRequest("current-password", "first-password"));
        userService.changePassword(user.getEmail(), new ChangePasswordRequest("first-password", "second-password"));
        User stored = users.findByEmail(user.getEmail()).orElseThrow();
        assertEquals(2L, stored.getSessionVersion());
        assertTrue(encoder.matches("second-password", stored.getPasswordHash()));
    }

    @Test
    void concurrentChangesCannotBothSucceedWithTheSameOldPassword() throws Exception {
        List<Future<String>> results = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(2)) {
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                // Hold the row until both workers reach a database lock. Without a locking
                // read, both validate the old hash and block only at UPDATE, then both win.
                jdbc.queryForObject("SELECT id FROM users WHERE email = ? FOR UPDATE", Long.class, user.getEmail());
                for (String next : List.of("first-password", "second-password")) {
                    results.add(executor.submit(() -> {
                        try {
                            userService.changePassword(user.getEmail(), new ChangePasswordRequest("current-password", next));
                            return next;
                        } catch (InvalidCredentialException rejected) {
                            return null;
                        }
                    }));
                }
                awaitBothDatabaseWaiters();
            });

            List<String> successfulPasswords = new ArrayList<>();
            for (var result : results) {
                String successfulPassword = result.get(15, TimeUnit.SECONDS);
                if (successfulPassword != null) successfulPasswords.add(successfulPassword);
            }
            assertEquals(1, successfulPasswords.size());
            User stored = users.findByEmail(user.getEmail()).orElseThrow();
            assertEquals(1L, stored.getSessionVersion());
            assertTrue(encoder.matches(successfulPasswords.getFirst(), stored.getPasswordHash()));
        }
    }

    private void awaitBothDatabaseWaiters() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        do {
            jdbc.execute("SELECT pg_stat_clear_snapshot()");
            Integer waiters = jdbc.queryForObject("SELECT count(*) FROM pg_stat_activity "
                    + "WHERE datname = current_database() AND wait_event_type = 'Lock'", Integer.class);
            if (waiters != null && waiters >= 2) return;
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(25));
        } while (System.nanoTime() < deadline);
        fail("Both password changes must reach a database lock before releasing the row");
    }

    private ResultActions changePassword(Cookie cookie, String current, String next) throws Exception {
        return mockMvc.perform(post("/api/auth/change-password").cookie(cookie).with(csrfCookieAndHeader())
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(
                        Map.of("currentPassword", current, "newPassword", next))));
    }

    private ResultActions login(String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login").with(csrfCookieAndHeader())
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(
                        Map.of("email", user.getEmail(), "password", password))));
    }
}
