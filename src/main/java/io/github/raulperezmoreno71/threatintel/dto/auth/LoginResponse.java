package io.github.raulperezmoreno71.threatintel.dto.auth;

import io.github.raulperezmoreno71.threatintel.model.UserStatus;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Response returned after a successful user login")
public class LoginResponse {

    @Schema(
            description = "Unique identifier of the authenticated user",
            examples = "1"
    )
    private Long id;

    @Schema(
            description = "Email address of the authenticated user",
            examples = "user@example.com"
    )
    private String email;

    @Schema(
            description = "Current status of the user account",
            examples = "ACTIVE"
    )
    private UserStatus status;

    @Schema(
            description = "Message indicating the result of the login operation",
            examples = "Login successfully"
    )
    private String message;

    public LoginResponse(
            Long id,
            String email,
            UserStatus status,
            String message
    ) {
        this.id = id;
        this.email = email;
        this.status = status;
        this.message = message;
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

    public String getMessage() {
        return message;
    }
}
