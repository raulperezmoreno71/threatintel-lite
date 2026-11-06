package io.github.raulperezmoreno71.threatintel.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

@Schema(description = "Save the authenticated user's temporary server-generated report. Report fields are ignored.")
public record SaveAnalysisRequest(
        @NotNull(message = "Pending analysis ID is required")
        @Schema(description = "Identifier returned by POST /api/analyze") UUID pendingAnalysisId
) {}
