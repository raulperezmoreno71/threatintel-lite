package io.github.raulperezmoreno71.threatintel.exception;

import io.github.raulperezmoreno71.threatintel.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.UUID;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(PendingAnalysisException.class)
    public ResponseEntity<ErrorResponse> handlePendingAnalysis(PendingAnalysisException exception, HttpServletRequest request) {
        return buildErrorResponse(exception.getStatus(), exception.getMessage(), request);
    }

    @ExceptionHandler(LoginRateLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleLoginRateLimitExceeded(LoginRateLimitExceededException exception, HttpServletRequest request) {
        ResponseEntity<ErrorResponse> response = buildErrorResponse(
                HttpStatus.TOO_MANY_REQUESTS, exception.getMessage(), request);
        return ResponseEntity.status(response.getStatusCode())
                .header(HttpHeaders.RETRY_AFTER, Long.toString(exception.getRetryAfterSeconds()))
                .body(response.getBody());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(MethodArgumentNotValidException exception, HttpServletRequest request) {
        String message = exception.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .distinct()
                .sorted()
                .collect(Collectors.joining("; "));

        return buildErrorResponse(HttpStatus.BAD_REQUEST, message, request);
    }

    @ExceptionHandler(AnalysisTimeoutException.class)
    public ResponseEntity<ErrorResponse> handleAnalysisTimeout(AnalysisTimeoutException exception, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.GATEWAY_TIMEOUT, exception.getMessage(), request);
    }

    @ExceptionHandler(DnsResolverBusyException.class)
    public ResponseEntity<ErrorResponse> handleDnsResolverBusy(DnsResolverBusyException exception, HttpServletRequest request) {
        return buildErrorResponse(HttpStatus.SERVICE_UNAVAILABLE, exception.getMessage(), request);
    }

    @ExceptionHandler(AnalysisNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAnalysisNotFoundException(AnalysisNotFoundException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.NOT_FOUND,
                exception.getMessage(),
                request
        );
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAnalysisNotFoundException(UserNotFoundException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.NOT_FOUND,
                exception.getMessage(),
                request
        );
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException (IllegalArgumentException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                exception.getMessage(),
                request
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException (HttpMessageNotReadableException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Malformed JSON request",
                request
        );
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> handleRuntimeException (RuntimeException exception, HttpServletRequest request) {
        String incidentId = UUID.randomUUID().toString();
        log.error("Unexpected error; incident ID: {}", incidentId, exception);
        ResponseEntity<ErrorResponse> response = buildErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred. Please try again later. Reference: " + incidentId,
                request
        );
        return ResponseEntity.status(response.getStatusCode())
                .header("X-Error-ID", incidentId)
                .body(response.getBody());
    }

    @ExceptionHandler(EmailAlreadyExistException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyExistException(EmailAlreadyExistException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.CONFLICT,
                exception.getMessage(),
                request
        );
    }

    @ExceptionHandler(InvalidCredentialException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentialException(InvalidCredentialException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                exception.getMessage(),
                request
        );
    }

    @ExceptionHandler(AnalysisRateLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleAnalysisRateLimitExceededException(AnalysisRateLimitExceededException exception, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.TOO_MANY_REQUESTS,
                exception.getMessage(),
                request
        );
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse (HttpStatus status, String message, HttpServletRequest request) {
        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                message,
                request.getRequestURI()
        );

        return ResponseEntity.status(status).body(errorResponse);
    }
}
