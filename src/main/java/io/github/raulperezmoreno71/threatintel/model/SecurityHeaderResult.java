package io.github.raulperezmoreno71.threatintel.model;

public class SecurityHeaderResult {
    private boolean present;
    private String value;

    public SecurityHeaderResult () {

    }

    public SecurityHeaderResult (boolean present, String value) {
        this.present = present;
        this.value = value;
    }

    public boolean isPresent() {
        return present;
    }

    public void setPresent(boolean present) {
        this.present = present;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
