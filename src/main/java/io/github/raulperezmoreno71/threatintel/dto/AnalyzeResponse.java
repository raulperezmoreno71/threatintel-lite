package io.github.raulperezmoreno71.threatintel.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SslAnalysisResult;

import java.util.List;

@JsonPropertyOrder({
        "message",
        "url",
        "domain",
        "ips",
        "httpStatusCode",
        "redirectLocation",
        "contentType",
        "server",
        "contentLength",
        "responseTimeMs",
        "ssl",
        "securityHeaders"
})

public class AnalyzeResponse {
    private String message;
    private String url;
    private String domain;
    private List<String> ips;
    private int httpStatusCode;
    private String redirectLocation;
    private String contentType;
    private String server;
    private Long contentLength;
    private long responseTimeMs;
    private SslAnalysisResult ssl;
    private SecurityHeadersAnalysisResult securityHeaders;

    public AnalyzeResponse () {

    }

    public AnalyzeResponse (
            String message,
            String url,
            String domain,
            List<String> ips,
            int httpStatusCode,
            String redirectLocation,
            String contentType,
            String server,
            Long contentLength,
            long responseTimeMs,
            SslAnalysisResult sslAnalysisResult,
            SecurityHeadersAnalysisResult securityHeaders
    ) {
        this.message = message;
        this.url = url;
        this.domain = domain;
        this.ips = ips;
        this.httpStatusCode = httpStatusCode;
        this.redirectLocation = redirectLocation;
        this.contentType = contentType;
        this.server = server;
        this.contentLength = contentLength;
        this.responseTimeMs = responseTimeMs;
        this.ssl = sslAnalysisResult;
        this.securityHeaders = securityHeaders;
    }

    public String getMessage () {return this.message;}

    public String getUrl () {return this.url;}

    public void setMessage (String message) {this.message = message;}

    public void setUrl (String url) {this.url = url;}

    public String getDomain () {return this.domain;}

    public void setDomain (String domain) {this.domain = domain;}

    public List<String> getIps () {return this.ips;}

    public void setIps (List<String> ips) {this.ips = ips;}

    public int getHttpStatusCode () {return this.httpStatusCode;}

    public void setHttpStatusCode (int httpStatusCode) {this.httpStatusCode = httpStatusCode;}

    public String getRedirectLocation () {return this.redirectLocation;}

    public void setRedirectLocation (String redirectLocation) {this.redirectLocation = redirectLocation;}

    public String getContentType () {return this.contentType;}

    public void setContentType (String contentType) {this.contentType = contentType;}

    public String getServer () {return this.server;}

    public void setServer (String server) {this.server = server;}

    public Long getContentLength () {return this.contentLength;}

    public void setContentLength (Long contentLength) {this.contentLength = contentLength;}

    public long getResponseTimeMs () {return this.responseTimeMs;}

    public void setResponseTimeMs (long responseTimeMs) {this.responseTimeMs = responseTimeMs;}

    public SslAnalysisResult getSsl() {return this.ssl;}

    public void setSsl(SslAnalysisResult sslAnalysisResult) {this.ssl = sslAnalysisResult;}

    public SecurityHeadersAnalysisResult getSecurityHeaders() {return this.securityHeaders;}

    public void setSecurityHeaders(SecurityHeadersAnalysisResult securityHeaders) {this.securityHeaders = securityHeaders;}
}
