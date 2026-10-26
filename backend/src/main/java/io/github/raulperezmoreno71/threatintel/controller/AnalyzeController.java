package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.dto.ErrorResponse;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisRateLimitExceededException;
import io.github.raulperezmoreno71.threatintel.service.AnalysisRateLimitService;
import io.github.raulperezmoreno71.threatintel.service.AnalyzeService;
import io.github.raulperezmoreno71.threatintel.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api")
@Tag(
        name = "URL Analysis",
        description = "Analyze URLs and retrieve DNS, HTTP, SSL/TLS and security information."
)
public class AnalyzeController {
    private final AnalyzeService analyzeService;
    private final AnalysisRateLimitService analysisRateLimitService;
    private final UserService userService;

    public AnalyzeController (
            AnalyzeService analyzeService,
            AnalysisRateLimitService analysisRateLimitService,
            UserService userService
    ) {
        this.analyzeService = analyzeService;
        this.analysisRateLimitService = analysisRateLimitService;
        this.userService = userService;
    }

    @Operation(
            summary =  "Analyze a URL",
            description = "Performs DNS resolution, HTTP analysis, redirect chain inspection, SSL/TLS certificate analysis, security header assessment and overall security score calculation."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "URL analyzed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = AnalyzeResponse.class
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid URL or malformed request",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            ),
                            examples = @ExampleObject(
                                    name = "Invalid URL",
                                    value = """
                                            {
                                                "status": 400,
                                                "error": "Bad Request",
                                                "message": "URL cannot be null or blank",
                                                "path": "/api/analyze"
                                            }
                                            """
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error during URL analysis.",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            ),
                            examples = @ExampleObject(
                                    name = "Analysis failure",
                                    value = """
                                            {
                                                "status": 500,
                                                "error": "Internal Server Error",
                                                "message": "Could not analyze SSL certificate",
                                                "path": "/api/analyze"
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/analyze")
    public AnalyzeResponse analyze (@RequestBody AnalyzeRequest request, Principal principal) {
        User user = userService.getByEmail(principal.getName());

        if (!analysisRateLimitService.tryAcquire(user.getId())) {
            throw new AnalysisRateLimitExceededException();
        }

        return analyzeService.analyze(request);
    }
}
