package io.github.raulperezmoreno71.threatintel.exception;

public class AnalysisRateLimitExceededException extends RuntimeException {
    public AnalysisRateLimitExceededException() {
        super("Too many analysis request. Please try again later.");
    }
}
