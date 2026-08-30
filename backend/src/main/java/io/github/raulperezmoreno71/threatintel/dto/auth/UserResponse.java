package io.github.raulperezmoreno71.threatintel.dto.auth;

import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Response containing information about the authenticated user")
public class UserResponse {

    @Schema(
            description = "Unique identifier of the user",
            examples = "1"
    )
    private Long id;

    @Schema(
            description = "Email address of the user",
            examples = "user@example.com"
    )
    private String email;

    @Schema(
            description = "Current status of the user",
            examples = "ACTIVE"
    )
    private UserStatus status;

    public UserResponse(Long id, String email, UserStatus status) {
        this.id = id;
        this.email = email;
        this.status = status;
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
}
