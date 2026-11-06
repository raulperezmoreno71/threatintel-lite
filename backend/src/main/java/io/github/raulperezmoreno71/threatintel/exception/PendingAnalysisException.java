package io.github.raulperezmoreno71.threatintel.exception;

import org.springframework.http.HttpStatus;

public class PendingAnalysisException extends RuntimeException {
    private final HttpStatus status;

    public PendingAnalysisException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() { return status; }
}
