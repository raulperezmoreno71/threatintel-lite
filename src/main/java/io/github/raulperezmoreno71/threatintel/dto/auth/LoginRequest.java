package io.github.raulperezmoreno71.threatintel.dto.auth;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Request payload used to authenticate a user")
public class LoginRequest {

    @Schema(
            description = "Email address of the user",
            examples = "user@example.com",
            requiredMode = Schema.RequiredMode.REQUIRED
    )
    private String email;

    @Schema(
            description = "Password provided by the user",
            examples = "StrongPassword123",
            requiredMode = Schema.RequiredMode.REQUIRED,
            format = "password"
    )
    private String password;

    public LoginRequest() {

    }

    public LoginRequest(String email, String password) {
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
