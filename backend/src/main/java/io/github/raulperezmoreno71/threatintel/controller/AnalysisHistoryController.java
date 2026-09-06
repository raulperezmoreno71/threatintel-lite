package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.dto.ErrorResponse;
import io.github.raulperezmoreno71.threatintel.dto.SaveAnalysisRequest;
import io.github.raulperezmoreno71.threatintel.service.AnalysisHistoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/analyses")
@Tag(
        name = "Analysis History",
        description = "Retrieve previously persisted URL analyses."
)
public class AnalysisHistoryController {

    private final AnalysisHistoryService analysisHistoryService;

    public AnalysisHistoryController(AnalysisHistoryService analysisHistoryService) {
        this.analysisHistoryService = analysisHistoryService;
    }

    @Operation(
            summary = "Retrieve stored analyses",
            description = "Returns all previously persisted URL analysis results."
    )
    @ApiResponse(
            responseCode = "200",
            description = "Stored analyses retrieved successfully."
    )
    @GetMapping
    public List<AnalysisHistoryResponse> getAllAnalyses() {
        return analysisHistoryService.getAllAnalyses();
    }

    @Operation(
            summary = "Retrieve a stored analysis by ID",
            description = "Returns a previously persisted URL analysis identified by its unique ID."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Analysis retrieved successfully"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Analysis not found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            )
                    )
            )
    })
    @GetMapping("/{id}")
    public AnalysisHistoryResponse getAnalysisById(@PathVariable Long id) {
        return analysisHistoryService.getAnalysisById(id);
    }

    @Operation(
            summary = "Delete a stored analysis",
            description = "Deletes a previously persisted URL analysis identified by its unique ID."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "204",
                    description = "Analysis deleted successfully"
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "Analysis not found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            )
                    )
            )
    })
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteAnalysisById(@PathVariable Long id) {
        analysisHistoryService.deleteAnalysisById(id);
    }

    @Operation(
            summary = "Save an analysis",
            description = "Persists a previously calculated URL analysis for the authenticated user."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "Analysis saved successfully"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid analysis data",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Authentication is required",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            )
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error while saving the analysis",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(
                                    implementation = ErrorResponse.class
                            )
                    )
            )
    })
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void saveAnalysis(@RequestBody SaveAnalysisRequest request) {
        analysisHistoryService.saveAnalysis(request);
    }
}
