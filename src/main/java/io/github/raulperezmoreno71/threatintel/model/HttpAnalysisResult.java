package io.github.raulperezmoreno71.threatintel.model;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.List;

@JsonPropertyOrder({
        "statusCode",
        "contentType",
        "server",
        "contentLength",
        "finalUrl",
        "totalResponseTimeMs",
        "redirectChain"
})

public class HttpAnalysisResult {
    private long totalResponseTimeMs;
    private int statusCode;
    private String contentType;
    private String server;
    private Long contentLength;
    private String finalUrl;
    private List<RedirectStep> redirectChain;

    public HttpAnalysisResult ()  {

    }

    public HttpAnalysisResult (
            int statusCode,
            String contentType,
            String server,
            Long contentLength,
            String finalUrl,
            long totalResponseTimeMs,
            List<RedirectStep> redirectChain
    ) {
        this.totalResponseTimeMs = totalResponseTimeMs;
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.server = server;
        this.contentLength = contentLength;
        this.finalUrl = finalUrl;
        this.redirectChain = redirectChain;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    public void setStatusCode(int httpStatusCode) {
        this.statusCode = httpStatusCode;
    }

    public long getTotalResponseTimeMs() {
        return this.totalResponseTimeMs;
    }

    public void setTotalResponseTimeMs (long totalResponseTimeMs) {
        this.totalResponseTimeMs = totalResponseTimeMs;
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

    public List<RedirectStep> getRedirectChain() {return this.redirectChain;}

    public void setRedirectChain(List<RedirectStep> redirectChain) {this.redirectChain = redirectChain;}

    public String getFinalUrl() {return this.finalUrl;}

    public void setFinalUrl(String finalUrl) {this.finalUrl = finalUrl;}
}
