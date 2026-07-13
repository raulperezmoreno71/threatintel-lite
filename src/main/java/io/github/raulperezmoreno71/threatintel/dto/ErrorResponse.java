package io.github.raulperezmoreno71.threatintel.dto;

public class ErrorResponse {
    private int status;
    private String error;
    private String message;
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
