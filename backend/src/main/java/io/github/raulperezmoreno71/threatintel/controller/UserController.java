package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.ChangePasswordRequest;
import io.github.raulperezmoreno71.threatintel.dto.ErrorResponse;
import io.github.raulperezmoreno71.threatintel.dto.auth.*;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.InvalidCredentialException;
import io.github.raulperezmoreno71.threatintel.service.LoginRateLimitService;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@Tag(
        name = "Authentication",
        description = "Endpoint for user registration and authentication"
)
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;
    private final LoginRateLimitService loginRateLimitService;

    @Value("${app.cookie.secure}")
    private boolean cookieSecure;

    public UserController(UserService userService, JwtService jwtService, LoginRateLimitService loginRateLimitService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.loginRateLimitService = loginRateLimitService;
    }

    @Operation(
            summary = "Register a new user",
            description = "Creates a new user account using the provided email and password."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "User registered successfully",
                    content = @Content(
                            schema = @Schema(implementation = RegisterResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "409",
                    description = "Email is already registered",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                               "status": 409,
                                               "error": "Conflict",
                                               "message": "Email is already registered",
                                               "path": "/api/auth/register"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or malformed  request",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                               "status": 400,
                                               "error": "Bad Request",
                                               "message": "Malformed JSON request",
                                               "path": "/api/auth/register"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = userService.register(request);

        RegisterResponse response = new RegisterResponse(
                user.getId(),
                user.getEmail(),
                user.getStatus(),
                user.getCreatedAt()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @Operation(
            summary = "Authenticate a user",
            description = "Authenticates a user using the provided email and password."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Login successful",
                    content = @Content(
                            schema = @Schema(implementation = LoginResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid email or password",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    name = "Invalid credentials",
                                    value = """
                                            {
                                                "status": 401,
                                                "error": "Unauthorized",
                                                "message": "Invalid email or password",
                                                "path": "/api/auth/login"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or malformed request",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    name = "Malformed Request",
                                    value = """
                                            {
                                                "status": 400,
                                                "error": "Bad Request",
                                                "message": "Malformed JSON request",
                                                "path": "/api/auth/login"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "429",
                    description = "Login attempt limit reached for this email",
                    headers = @Header(name = "Retry-After", description = "Seconds before retrying",
                            schema = @Schema(type = "integer", format = "int64")),
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))
            )
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        User user;
        try (var attempt = loginRateLimitService.acquire(request.getEmail())) {
            try {
                user = userService.login(request);
            } catch (InvalidCredentialException invalidCredentials) {
                attempt.failed();
                throw invalidCredentials;
            }
            attempt.succeeded();
        }

        ResponseCookie cookie = createAccessTokenCookie(user);

        LoginResponse response = new LoginResponse(
                user.getId(),
                user.getEmail(),
                user.getStatus(),
                "Login successful"
        );

        return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, cookie.toString()).body(response);
    }

    @Operation(
            summary = "Get authenticated user",
            description = "Returns the email of the currently authenticated user."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Authenticated user retrieved successfully",
                    content = @Content(
                            schema = @Schema(implementation = UserResponse.class),
                            examples = @ExampleObject(
                                    name = "Authenticated user",
                                    value = """
                                            {
                                                "id": 1,
                                                "email": "user@example.com",
                                                "status": "ACTIVE"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication required or invalid token",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    name = "Unauthorized",
                                    value = """
                                        {
                                            "status": 401,
                                            "error": "Unauthorized",
                                            "message": "Authentication is required",
                                            "path": "/api/auth/me"
                                        }
                                        """
                            )
                    )
            )
    })
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me(Authentication authentication) {
        User user = userService.getByEmail(authentication.getName());

        UserResponse response = new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getStatus()
        );

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Log out authenticated user",
            description = "Logs out the current user by deleting the authentication cookie."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Logout successful"
            )
    })
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        ResponseCookie cookie = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();

        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
    }

    @Operation(
            summary = "Change authenticated user's password",
            description = "Changes the password after verifying the current password, revokes earlier tokens and renews the current access cookie."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Password changed successfully and current access cookie renewed"
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication required or current password is incorrect",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    name = "Invalid current password",
                                    value = """
                                        {
                                            "status": 401,
                                            "error": "Unauthorized",
                                            "message": "Invalid password",
                                            "path": "/api/auth/change-password"
                                        }
                                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Authenticated user not found",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    name = "User not found",
                                    value = """
                                        {
                                            "status": 404,
                                            "error": "Not Found",
                                            "message": "User not found",
                                            "path": "/api/auth/change-password"
                                        }
                                        """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or malformed request",
                    content = @Content(
                            schema = @Schema(implementation = ErrorResponse.class),
                            examples = @ExampleObject(
                                    name = "Malformed request",
                                    value = """
                                        {
                                            "status": 400,
                                            "error": "Bad Request",
                                            "message": "Malformed JSON request",
                                            "path": "/api/auth/change-password"
                                        }
                                        """
                            )
                    )
            )
    })
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePasswordRequest request, Authentication authentication) {
        User user = userService.changePassword(authentication.getName(), request);
        ResponseCookie cookie = createAccessTokenCookie(user);

        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
    }

    private ResponseCookie createAccessTokenCookie(User user) {
        return ResponseCookie.from("access_token", jwtService.generateToken(user))
                .httpOnly(true)
                .secure(cookieSecure)
                .sameSite("Lax")
                .path("/")
                .build();
    }
}
