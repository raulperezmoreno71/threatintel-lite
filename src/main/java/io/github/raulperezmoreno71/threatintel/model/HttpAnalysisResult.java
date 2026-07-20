package io.github.raulperezmoreno71.threatintel.model;

public class HttpAnalysisResult {
    private long responseTimeMs;
    private int statusCode;
    private String redirectLocation;
    private String contentType;
    private String server;
    private Long contentLength;

    public HttpAnalysisResult ()  {

    }

    public HttpAnalysisResult (
            int statusCode,
            String redirectLocation,
            String contentType,
            String server,
            Long contentLength,
            long resposteTimeMs
    ) {
        this.responseTimeMs = resposteTimeMs;
        this.statusCode = statusCode;
        this.redirectLocation = redirectLocation;
        this.contentType = contentType;
        this.server = server;
        this.contentLength = contentLength;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public void setStatusCode(int httpStatusCode) {
        this.statusCode = httpStatusCode;
    }

    public long getResponseTimeMs() {
        return this.responseTimeMs;
    }

    public void setResponseTimeMs (long resposteTimeMs) {
        this.responseTimeMs = resposteTimeMs;
    }

    public String getRedirectLocation() {
        return this.redirectLocation;
    }

    public void setRedirectLocation(String redirectLocation) {
        this.redirectLocation = redirectLocation;
    }

    public String getContentType() {
        return this.contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getServer() {
        return this.server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public Long getContentLength() {
        return this.contentLength;
    }

    public void setContentLength(Long contentLength) {
        this.contentLength = contentLength;
    }
}
