package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Schema(
        description = "Contains the analysis result of the evaluated HTTP security headers."
)
public class SecurityHeadersAnalysisResult {

    @Schema(
            description = "Analysis of the HTTP Strict-Transport-Security (HSTS) header."
    )
    @NotNull(message = "HSTS result is required")
    @Valid
    private SecurityHeaderResult strictTransportSecurity;

    @Schema(
            description = "Analysis of the Content-Security-Policy (CSP) header."
    )
    @NotNull(message = "CSP result is required")
    @Valid
    private SecurityHeaderResult contentSecurityPolicy;

    @Schema(
            description = "Analysis of the X-Frame-Options header."
    )
    @NotNull(message = "X-Frame-Options result is required")
    @Valid
    private SecurityHeaderResult xFrameOptions;

    @Schema(
            description = "Analysis of the X-Content-Type-Options header."
    )
    @NotNull(message = "X-Content-Type-Options result is required")
    @Valid
    private SecurityHeaderResult xContentTypeOptions;

    @Schema(
            description = "Analysis of the Referrer-Policy header."
    )
    @NotNull(message = "Referrer-Policy result is required")
    @Valid
    private SecurityHeaderResult referrerPolicy;

    @Schema(
            description = "Analysis of the Permission-Policy header."
    )
    @NotNull(message = "Permissions-Policy result is required")
    @Valid
    private SecurityHeaderResult permissionsPolicy;

    public SecurityHeadersAnalysisResult() {

    }

    public SecurityHeadersAnalysisResult(
            SecurityHeaderResult strictTransportSecurity,
            SecurityHeaderResult contentSecurityPolicy,
            SecurityHeaderResult xFrameOptions,
            SecurityHeaderResult xContentTypeOptions,
            SecurityHeaderResult referrerPolicy,
            SecurityHeaderResult permissionsPolicy
    ) {
        this.strictTransportSecurity = strictTransportSecurity;
        this.contentSecurityPolicy = contentSecurityPolicy;
        this.xFrameOptions = xFrameOptions;
        this.xContentTypeOptions = xContentTypeOptions;
        this.referrerPolicy = referrerPolicy;
        this.permissionsPolicy = permissionsPolicy;
    }

    public SecurityHeaderResult getStrictTransportSecurity() {
        return strictTransportSecurity;
    }

    public void setStrictTransportSecurity(SecurityHeaderResult strictTransportSecurity) {
        this.strictTransportSecurity = strictTransportSecurity;
    }

    public SecurityHeaderResult getContentSecurityPolicy() {
        return contentSecurityPolicy;
    }

    public void setContentSecurityPolicy(SecurityHeaderResult contentSecurityPolicy) {
        this.contentSecurityPolicy = contentSecurityPolicy;
    }

    public SecurityHeaderResult getXFrameOptions() {
        return xFrameOptions;
    }

    public void setXFrameOptions(SecurityHeaderResult xFrameOptions) {
        this.xFrameOptions = xFrameOptions;
    }

    public SecurityHeaderResult getXContentTypeOptions() {
        return xContentTypeOptions;
    }

    public void setXContentTypeOptions(SecurityHeaderResult xContentTypeOptions) {
        this.xContentTypeOptions = xContentTypeOptions;
    }

    public SecurityHeaderResult getReferrerPolicy() {
        return referrerPolicy;
    }

    public void setReferrerPolicy(SecurityHeaderResult referrerPolicy) {
        this.referrerPolicy = referrerPolicy;
    }

    public SecurityHeaderResult getPermissionsPolicy() {
        return permissionsPolicy;
    }

    public void setPermissionsPolicy(SecurityHeaderResult permissionsPolicy) {
        this.permissionsPolicy = permissionsPolicy;
    }
}
