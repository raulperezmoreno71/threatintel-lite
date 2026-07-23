package io.github.raulperezmoreno71.threatintel.model;

public class SecurityAssessmentResult {
    private int score;
    private String grade;
    private int goodHeaders;
    private int warningHeaders;
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
