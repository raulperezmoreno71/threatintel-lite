package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import io.github.raulperezmoreno71.threatintel.service.AnalysisHistoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public List<Analysis> getAllAnalyses() {
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
}
