package io.github.raulperezmoreno71.threatintel.exception;

public class SslTimeoutException extends RuntimeException {

    public SslTimeoutException (String message, Throwable cause) {
        super(message, cause);
    }
}
