package io.github.raulperezmoreno71.threatintel.dto.auth;

import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

@Schema(description = "Response returned after a user is successfully registered")
public class RegisterResponse {

    @Schema(
            description = "Unique identifier of the registered user",
            example = "1"
    )
    private Long id;

    @Schema(
            description = "Email address of the registered user",
            example = "user@example.com"
    )
    private String email;

    @Schema(
            description = "Current status of the user account",
            example = "ACTIVE"
    )
    private UserStatus status;

    @Schema(
            description = "Date and time when the user account was created",
            example = "2026-08-20T12:45:30"
    )
    private LocalDateTime createdAt;

    public RegisterResponse(
            Long id,
            String email,
            UserStatus status,
            LocalDateTime createdAt
    ) {
        this.id = id;
        this.email = email;
        this.status = status;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public UserStatus getStatus() {
        return status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
}
