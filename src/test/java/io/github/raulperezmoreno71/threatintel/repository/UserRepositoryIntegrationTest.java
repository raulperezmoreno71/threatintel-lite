package io.github.raulperezmoreno71.threatintel.repository;

import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Testcontainers
@AutoConfigureTestDatabase(
        replace = AutoConfigureTestDatabase.Replace.NONE
)
class UserRepositoryIntegrationTest {

    @Container
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16")
            .withDatabaseName("threatintel_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AnalysisRepository analysisRepository;

    @Autowired
    private EntityManager entityManager;

    @Test
    void shouldSaveAndFindUserByEmail() {
        User user = new User(
                "raul@example.com",
                "password",
                UserStatus.ACTIVE
        );

        User saved = userRepository.saveAndFlush(user);

        Optional<User> found = userRepository.findByEmail("raul@example.com");

        assertTrue(found.isPresent());
        assertNotNull(saved.getId());
        assertEquals("raul@example.com", found.get().getEmail());
        assertEquals("password", found.get().getPasswordHash());
        assertEquals(UserStatus.ACTIVE, found.get().getStatus());
        assertNotNull(found.get().getCreatedAt());
        assertNotNull(found.get().getUpdatedAt());
    }

    @Test
    void shouldDetectExistingUserByEmail() {
        User user = new User(
                "raul@example.com",
                "password",
                UserStatus.ACTIVE
        );

        userRepository.saveAndFlush(user);

        boolean found = userRepository.existsByEmail("raul@example.com");
        boolean invented = userRepository.existsByEmail("test@example.com");

        assertTrue(found);
        assertFalse(invented);
    }

    @Test
    void shouldRejectDuplicatedEmail() {
        User user1 = new User(
                "raul@example.com",
                "password",
                UserStatus.ACTIVE
        );

        User user2 = new User(
                "raul@example.com",
                "password",
                UserStatus.ACTIVE
        );

        userRepository.saveAndFlush(user1);

        assertThrows(
                DataIntegrityViolationException.class,
                () -> userRepository.saveAndFlush(user2)
        );
    }

    @Test
    void shouldPersistAnalysisWithUser() {
        User user = new User(
                "raul@example.com",
                "password",
                UserStatus.ACTIVE
        );

        User savedUser = userRepository.saveAndFlush(user);

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                null,
                null,
                null,
                null,
                null
        );

        savedUser.addAnalysis(analysis);

        Analysis savedAnalysis = analysisRepository.saveAndFlush(analysis);

        entityManager.clear();

        Analysis found = entityManager.find(Analysis.class, savedAnalysis.getId());

        assertNotNull(found);
        assertNotNull(found.getUser());
        assertEquals(savedUser.getId(), found.getUser().getId());
        assertEquals("raul@example.com", found.getUser().getEmail());
    }

    @Test
    void shouldRetrieveUserWithPersistedAnalysis() {
        User user = new User(
                "raul@example.com",
                "password",
                UserStatus.ACTIVE
        );

        User savedUser = userRepository.saveAndFlush(user);

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                null,
                null,
                null,
                null,
                null
        );

        savedUser.addAnalysis(analysis);

        analysisRepository.saveAndFlush(analysis);

        entityManager.clear();

        User found = entityManager.find(User.class, savedUser.getId());

        assertNotNull(found);
        assertEquals(1, found.getAnalyses().size());
        assertEquals("https://example.com", found.getAnalyses().get(0).getUrl());
    }

    @Test
    void shouldRejectAnalysisWithoutUser() {
        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                null,
                null,
                null,
                null,
                null
        );

        assertThrows(
                DataIntegrityViolationException.class,
                () -> analysisRepository.saveAndFlush(analysis)
        );
    }
}
