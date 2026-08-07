package io.github.raulperezmoreno71.threatintel.exception;

public class TooManyRedirectsException extends RuntimeException{

    public TooManyRedirectsException(String message) {
        super(message);
    }
}
