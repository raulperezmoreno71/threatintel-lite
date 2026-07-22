package io.github.raulperezmoreno71.threatintel.model;

public class SecurityHeaderResult {
    private boolean present;
    private String value;
    private SecurityStatus status;
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
