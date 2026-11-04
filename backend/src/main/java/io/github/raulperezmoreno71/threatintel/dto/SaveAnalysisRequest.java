package io.github.raulperezmoreno71.threatintel.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@JsonPropertyOrder({
        "message",
        "url",
        "domain",
        "dns",
        "http",
        "ssl",
        "securityHeaders",
        "securityAssessment"
})

@Schema(
        description = "Complete result of the URL analysis."
)
public class SaveAnalysisRequest {

    @Schema(
            description = "Analysis execution result message.",
            example = "URL analyzed successfully."
    )
    @Size(max = 255, message = "Message must not exceed 255 characters")
    private String message;

    @Schema(
            description = "Normalized URL that was analyzed.",
            example = "https://github.com"
    )
    @NotBlank(message = "URL is required")
    @Size(max = 255, message = "Saved URL must not exceed 255 characters")
    private String url;

    @Schema(
            description = "Extracted domain name.",
            example = "github.com"
    )
    @NotBlank(message = "Domain is required")
    @Size(max = 253, message = "Domain must not exceed 253 characters")
    private String domain;

    @Schema(
            description = "DNS resolution results."
    )
    @NotNull(message = "DNS results are required")
    @Valid
    private DnsAnalysisResult dns;

    @Schema(
            description = "HTTP response analysis."
    )
    @NotNull(message = "HTTP results are required")
    @Valid
    private HttpAnalysisResult http;

    @Schema(
            description = "SSL/TLS certificate analysis."
    )
    @Valid
    private SslAnalysisResult ssl;

    @Schema(
            description = "Assessment of common HTTP security headers."
    )
    @NotNull(message = "Security header results are required")
    @Valid
    private SecurityHeadersAnalysisResult securityHeaders;

    @Schema(
            description = "Overall website security assessment calculated from the analyzed security headers."
    )
    @NotNull(message = "Security assessment is required")
    @Valid
    private SecurityAssessmentResult securityAssessment;

    public SaveAnalysisRequest () {

    }

    public SaveAnalysisRequest (
            String message,
            String url,
            String domain,
            DnsAnalysisResult dns,
            HttpAnalysisResult http,
            SslAnalysisResult ssl,
            SecurityHeadersAnalysisResult securityHeaders,
            SecurityAssessmentResult securityAssessment
    ) {
        this.message = message;
        this.url = url;
        this.domain = domain;
        this.dns = dns;
        this.http = http;
        this.ssl = ssl;
        this.securityHeaders = securityHeaders;
        this.securityAssessment = securityAssessment;
    }

    public String getMessage () {return this.message;}

    public String getUrl () {return this.url;}

    public void setMessage (String message) {this.message = message;}

    public void setUrl (String url) {this.url = url;}

    public String getDomain () {return this.domain;}

    public void setDomain (String domain) {this.domain = domain;}

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
