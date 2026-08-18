package io.github.raulperezmoreno71.threatintel.repository;

import io.github.raulperezmoreno71.threatintel.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
