package io.github.raulperezmoreno71.threatintel.model;


import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.*;

@Schema(
        description = "Provides an overall security assessment based on the analyzed HTTP security headers."
)
public class SecurityAssessmentResult {

    @Schema(
            description = "Overall security score calculated from the analyzed HTTP security headers.",
            example = "75"
    )
    @NotNull(message = "Score is required")
    @Min(value = 0, message = "Score must be between 0 and 100")
    @Max(value = 100, message = "Score must be between 0 and 100")
    private Integer score;

    @Schema(
            description = "Letter grade assigned to the overall security score.",
            example = "C"
    )
    @NotNull(message = "Grade is required")
    @Pattern(regexp = "[ABCDF]", message = "Grade must be A, B, C, D or F")
    private String grade;

    @Schema(
            description = "Number of security headers classified as GOOD",
            example = "4"
    )
    @NotNull(message = "Good header count is required")
    @Min(value = 0, message = "Header count must be between 0 and 6")
    @Max(value = 6, message = "Header count must be between 0 and 6")
    private Integer goodHeaders;

    @Schema(
            description = "Number of security headers classified as WARNING.",
            example = "1"
    )
    @NotNull(message = "Warning header count is required")
    @Min(value = 0, message = "Header count must be between 0 and 6")
    @Max(value = 6, message = "Header count must be between 0 and 6")
    private Integer warningHeaders;

    @Schema(
            description = "Number of security headers classified as MISSING.",
            example = "1"
    )
    @NotNull(message = "Missing header count is required")
    @Min(value = 0, message = "Header count must be between 0 and 6")
    @Max(value = 6, message = "Header count must be between 0 and 6")
    private Integer missingHeaders;

    public SecurityAssessmentResult () {

    }

    @JsonCreator(mode = JsonCreator.Mode.DISABLED)
    public SecurityAssessmentResult (
            int score,
            String grade,
            int goodHeaders,
            int warningHeaders,
            int missingHeaders
    ) {
        this.score = score;
        this.grade = grade;
        this.goodHeaders = goodHeaders;
        this.warningHeaders = warningHeaders;
        this.missingHeaders = missingHeaders;
    }

    public Integer getScore() {
        return score;
    }

    public void setScore(Integer score) {
        this.score = score;
    }

    public String getGrade() {
        return grade;
    }

    public void setGrade(String grade) {
        this.grade = grade;
    }

    public Integer getGoodHeaders() {
        return goodHeaders;
    }

    public void setGoodHeaders(Integer goodHeaders) {
        this.goodHeaders = goodHeaders;
    }

    public Integer getWarningHeaders() {
        return warningHeaders;
    }

    public void setWarningHeaders(Integer warningHeaders) {
        this.warningHeaders = warningHeaders;
    }

    public Integer getMissingHeaders() {
        return missingHeaders;
    }

    public void setMissingHeaders(Integer missingHeaders) {
        this.missingHeaders = missingHeaders;
    }
}
