package io.github.raulperezmoreno71.threatintel.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Request payload used to register a new user")
public class RegisterRequest {

    @Schema(
            description = "Email address for the user",
            example = "user@example.com",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String email;

    @Schema(
            description = "Plain-text password provided during registration",
            example = "StrongPassword123",
            requiredMode = Schema.RequiredMode.REQUIRED,
            format = "password"
    )
    private String password;

    public RegisterRequest() {

    }

    public RegisterRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
