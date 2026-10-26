package io.github.raulperezmoreno71.threatintel.exception;

public class AnalysisTimeoutException extends RuntimeException {
    public AnalysisTimeoutException() {
        super("Analysis time limit exceeded");
    }
}
