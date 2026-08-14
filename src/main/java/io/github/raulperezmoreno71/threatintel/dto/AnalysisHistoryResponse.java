package io.github.raulperezmoreno71.threatintel.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDate;
import java.time.LocalDateTime;

@JsonPropertyOrder({
        "id",
        "message",
        "url",
        "domain",
        "createdAt",
        "dns",
        "http",
        "ssl",
        "securityHeaders",
        "securityAssessment"
})

@Schema(
            description = "Represents a previously stored URL analysis."
)
public class AnalysisHistoryResponse {

    @Schema(
            description = "Unique identifier of the stored analysis.",
            example = "32"
    )
    private Long id;

    @Schema(
            description = "Analysis execution result message.",
            example = "URL analyzed successfully."
    )
    private String message;

    @Schema(
            description = "Normalized URL that was analyzed.",
            example = "https://github.com"
    )
    private String url;

    @Schema(
            description = "Extracted domain name.",
            example = "github.com"
    )
    private String domain;

    @Schema(
            description = "When the analysis was performed.",
            example = "2026-08-09 20:01:57.143491"
    )
    private LocalDateTime createdAt;

    @Schema(
            description = "DNS resolution results."
    )
    private DnsAnalysisResult dns;

    @Schema(
            description = "HTTP response analysis."
    )
    private HttpAnalysisResult http;

    @Schema(
            description = "SSL/TLS certificate analysis."
    )
    private SslAnalysisResult ssl;

    @Schema(
            description = "Assessment of common HTTP security headers."
    )
    private SecurityHeadersAnalysisResult securityHeaders;

    @Schema(
            description = "Overall website security assessment calculated from the analyzed security headers."
    )
    private SecurityAssessmentResult securityAssessment;

    public AnalysisHistoryResponse () {

    }

    public AnalysisHistoryResponse (
            Long id,
            String message,
            String url,
            String domain,
            LocalDateTime createdAt,
            DnsAnalysisResult dns,
            HttpAnalysisResult http,
            SslAnalysisResult ssl,
            SecurityHeadersAnalysisResult securityHeaders,
            SecurityAssessmentResult securityAssessment
    ) {
        this.id = id;
        this.message = message;
        this.url = url;
        this.domain = domain;
        this.createdAt = createdAt;
        this.dns = dns;
        this.http = http;
        this.ssl = ssl;
        this.securityHeaders = securityHeaders;
        this.securityAssessment = securityAssessment;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMessage () {return this.message;}

    public String getUrl () {return this.url;}

    public void setMessage (String message) {this.message = message;}

    public void setUrl (String url) {this.url = url;}

    public String getDomain () {return this.domain;}

    public void setDomain (String domain) {this.domain = domain;}

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public DnsAnalysisResult getDns () {return this.dns;}

    public void setDns(DnsAnalysisResult dns) {this.dns = dns;}

    public HttpAnalysisResult getHttp() {return this.http;}

    public void setHttp(HttpAnalysisResult http) {this.http = http;}

    public SslAnalysisResult getSsl() {return this.ssl;}

    public void setSsl(SslAnalysisResult ssl) {this.ssl = ssl;}

    public SecurityHeadersAnalysisResult getSecurityHeaders() {return this.securityHeaders;}

    public void setSecurityHeaders(SecurityHeadersAnalysisResult securityHeaders) {this.securityHeaders = securityHeaders;}

    public SecurityAssessmentResult getSecurityAssessment () {return this.securityAssessment;}

    public void setSecurityAssessment (SecurityAssessmentResult securityAssessment) {this.securityAssessment = securityAssessment;}
}
