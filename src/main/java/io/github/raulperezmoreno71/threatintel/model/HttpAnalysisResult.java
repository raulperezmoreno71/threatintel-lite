package io.github.raulperezmoreno71.threatintel.model;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.v3.oas.annotations.media.Schema;

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

@Schema(
        description = "Contains the results of the HTTP analysis performed on the analyzed URL."
)
public class HttpAnalysisResult {
    @Schema(
            description = "The total time in milliseconds of the http request.",
            example = "623"
    )
    private long totalResponseTimeMs;

    @Schema(
            description = "The status code returned by the last server.",
            example = "200"
    )
    private int statusCode;

    @Schema(
            description = "Content type returned by the HTTP response.",
            example = "application/json"
    )
    private String contentType;

    @Schema(
            description = "Server identifier returned in the HTTP request.",
            example = "github.com"
    )
    private String server;

    @Schema(
            description = "The total length of the message expressed in bytes.",
            example = "1260"
    )
    private Long contentLength;

    @Schema(
            description = "Final URL after following all HTTP redirects.",
            example = "https://github.com/"
    )
    private String finalUrl;

    @Schema(
            description = "List of all HTTP redirection steps followed during the request."
    )
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
