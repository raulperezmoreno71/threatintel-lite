package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Schema(
        description = "Represents the analysis result of a single security header."
)
public class SecurityHeaderResult {

    @Schema(
            description = "Indicates whether the header is present.",
            example = "true"
    )
    @NotNull(message = "Header presence is required")
    private Boolean present;

    @Schema(
            description = "Value of the detected security header.",
            example = "max-age=31536000; includeSubdomains; preload"
    )
    @Size(max = 8192, message = "Header value must not exceed 8192 characters")
    private String value;

    @Schema(
            description = "Security classification assigned to the analyzed header.",
            example = "GOOD"
    )
    @NotNull(message = "Header status is required")
    private SecurityStatus status;

    @Schema(
            description = "Recommendation to improve the security configuration when applicable.",
            example = "Avoid using 'unsafe-inline'. Use nonces or hashes for required inline scripts and styles."
    )
    @Size(max = 2048, message = "Header recommendation must not exceed 2048 characters")
    private String recommendation;

    public SecurityHeaderResult () {

    }

    @JsonCreator(mode = JsonCreator.Mode.DISABLED)
    public SecurityHeaderResult (boolean present, String value, SecurityStatus status, String recommendation) {
        this.present = present;
        this.value = value;
        this.status = status;
        this.recommendation = recommendation;
    }

    public Boolean isPresent() {
        return present;
    }

    public void setPresent(Boolean present) {this.present = present;}

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
