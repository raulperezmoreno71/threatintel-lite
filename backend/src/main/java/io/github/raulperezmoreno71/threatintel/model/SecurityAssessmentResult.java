package io.github.raulperezmoreno71.threatintel.model;


import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Provides an overall security assessment based on the analyzed HTTP security headers."
)
public class SecurityAssessmentResult {

    @Schema(
            description = "Overall security score calculated from the analyzed HTTP security headers.",
            example = "75"
    )
    private int score;

    @Schema(
            description = "Letter grade assigned to the overall security score.",
            example = "C"
    )
    private String grade;

    @Schema(
            description = "Number of security headers classified as GOOD",
            example = "4"
    )
    private int goodHeaders;

    @Schema(
            description = "Number of security headers classified as WARNING.",
            example = "1"
    )
    private int warningHeaders;

    @Schema(
            description = "Number of security headers classified as MISSING.",
            example = "1"
    )
    private int missingHeaders;

    public SecurityAssessmentResult () {

    }

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

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getGrade() {
        return grade;
    }

    public void setGrade(String grade) {
        this.grade = grade;
    }

    public int getGoodHeaders() {
        return goodHeaders;
    }

    public void setGoodHeaders(int goodHeaders) {
        this.goodHeaders = goodHeaders;
    }

    public int getWarningHeaders() {
        return warningHeaders;
    }

    public void setWarningHeaders(int warningHeaders) {
        this.warningHeaders = warningHeaders;
    }

    public int getMissingHeaders() {
        return missingHeaders;
    }

    public void setMissingHeaders(int missingHeaders) {
        this.missingHeaders = missingHeaders;
    }
}
