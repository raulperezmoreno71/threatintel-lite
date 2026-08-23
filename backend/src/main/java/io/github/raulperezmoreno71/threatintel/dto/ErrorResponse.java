package io.github.raulperezmoreno71.threatintel.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema (
        description = "Standard error response returned when a request cannot be processed."
)
public class ErrorResponse {

    @Schema(
            description = "HTTP status code."
    )
    private int status;

    @Schema(
            description = "HTTP error description."
    )
    private String error;

    @Schema(
            description = "Detailed explanation of the error."
    )
    private String message;

    @Schema(
            description = "API endpoint where the error occurred."
    )
    private String path;

    public ErrorResponse () {

    }

    public ErrorResponse (int status, String error, String message, String path) {
        this.status = status;
        this.error = error;
        this.message = message;
        this.path = path;
    }

    public int getStatus () {return this.status;}

    public void setStatus (int status) {
        this.status = status;
    }

    public String getError () {return this.error;}

    public void setError (String error) {
        this.error = error;
    }

    public String getMessage () {return this.message;}

    public void setMessage (String message) {
        this.message = message;
    }

    public String getPath () {return this.path;}

    public void setPath (String path) {
        this.path = path;
    }
}
