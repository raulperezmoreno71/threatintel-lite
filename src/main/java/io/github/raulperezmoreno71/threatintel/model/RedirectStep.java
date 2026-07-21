package io.github.raulperezmoreno71.threatintel.model;

public class RedirectStep {
    private String url;
    private int statusCode;
    private String location;
    private long responseTimeMs;

    public RedirectStep () {

    }

    public RedirectStep (String url, int statusCode, String location, long responseTimeMs) {
        this.url = url;
        this.statusCode = statusCode;
        this.location = location;
        this.responseTimeMs = responseTimeMs;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }
}
