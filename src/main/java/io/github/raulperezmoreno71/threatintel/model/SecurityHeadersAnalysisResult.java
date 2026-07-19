package io.github.raulperezmoreno71.threatintel.model;

public class SecurityHeadersAnalysisResult {
    private SecurityHeaderResult strictTransportSecurity;
    private SecurityHeaderResult contentSecurityPolicy;
    private SecurityHeaderResult xFrameOptions;
    private SecurityHeaderResult xContentTypeOptions;
    private SecurityHeaderResult referrerPolicy;
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
