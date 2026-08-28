package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.ErrorResponse;
import io.github.raulperezmoreno71.threatintel.dto.auth.LoginRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.LoginResponse;
import io.github.raulperezmoreno71.threatintel.dto.auth.RegisterRequest;
import io.github.raulperezmoreno71.threatintel.dto.auth.RegisterResponse;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.service.JwtService;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@Tag(
        name = "Authentication",
        description = "Endpoint for user registration and authentication"
)
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;

    public UserController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
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
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest request) {
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
                                                "erro": Unauthorized",
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
            )
    })
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        User user = userService.login(request);

        String token = jwtService.generateToken(user);

        ResponseCookie cookie = ResponseCookie.from("access_token", token)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .build();

        LoginResponse response = new LoginResponse(
                user.getId(),
                user.getEmail(),
                user.getStatus(),
                "Login successful"
        );

        return ResponseEntity.status(HttpStatus.OK).header(HttpHeaders.SET_COOKIE, cookie.toString()).body(response);
    }
}
