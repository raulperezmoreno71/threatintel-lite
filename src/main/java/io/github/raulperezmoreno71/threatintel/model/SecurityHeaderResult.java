package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Represents the analysis result of a single security header."
)
public class SecurityHeaderResult {

    @Schema(
            description = "Indicates whether the header is present.",
            example = "true"
    )
    private boolean present;

    @Schema(
            description = "Value of the detected security header.",
            example = "max-age=31536000; includeSubdomains; preload"
    )
    private String value;

    @Schema(
            description = "Security classification assigned to the analyzed header.",
            example = "GOOD"
    )
    private SecurityStatus status;

    @Schema(
            description = "Recommendation to improve the security configuration when applicable.",
            example = "Avoid using 'unsafe-inline'. Use nonces or hashes for required inline scripts and styles."
    )
    private String recommendation;

    public SecurityHeaderResult () {

    }

    public SecurityHeaderResult (boolean present, String value, SecurityStatus status, String recommendation) {
        this.present = present;
        this.value = value;
        this.status = status;
        this.recommendation = recommendation;
    }

    public boolean isPresent() {
        return present;
    }

    public void setPresent(boolean present) {this.present = present;}

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public SecurityStatus getStatus() {
        return status;
    }

    public void setStatus(SecurityStatus status) {
        this.status = status;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }
}
