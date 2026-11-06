package io.github.raulperezmoreno71.threatintel.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.UUID;

@Schema(description = "Server-generated report retained temporarily for the authenticated user.")
public class PendingAnalysisResponse extends AnalyzeResponse {
    private final UUID pendingAnalysisId;
    private final Instant expiresAt;

    public PendingAnalysisResponse(AnalyzeResponse report, UUID pendingAnalysisId, Instant expiresAt) {
        super(report.getMessage(), report.getUrl(), report.getDomain(), report.getDns(), report.getHttp(),
                report.getSsl(), report.getSecurityHeaders(), report.getSecurityAssessment());
        this.pendingAnalysisId = pendingAnalysisId;
        this.expiresAt = expiresAt;
    }

    public UUID getPendingAnalysisId() { return pendingAnalysisId; }
    public Instant getExpiresAt() { return expiresAt; }
}
