package io.github.raulperezmoreno71.threatintel.dto;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.github.raulperezmoreno71.threatintel.model.DnsAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.HttpAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SslAnalysisResult;

@JsonPropertyOrder({
        "message",
        "url",
        "domain",
        "dns",
        "http",
        "ssl",
        "securityHeaders"
})

public class AnalyzeResponse {
    private String message;
    private String url;
    private String domain;

    private DnsAnalysisResult dns;
    private HttpAnalysisResult http;
    private SslAnalysisResult ssl;
    private SecurityHeadersAnalysisResult securityHeaders;

    public AnalyzeResponse () {

    }

    public AnalyzeResponse (
            String message,
            String url,
            String domain,
            DnsAnalysisResult dns,
            HttpAnalysisResult http,
            SslAnalysisResult ssl,
            SecurityHeadersAnalysisResult securityHeaders
    ) {
        this.message = message;
        this.url = url;
        this.domain = domain;
        this.dns = dns;
        this.http = http;
        this.ssl = ssl;
        this.securityHeaders = securityHeaders;
    }

    public String getMessage () {return this.message;}

    public String getUrl () {return this.url;}

    public void setMessage (String message) {this.message = message;}

    public void setUrl (String url) {this.url = url;}

    public String getDomain () {return this.domain;}

    public void setDomain (String domain) {this.domain = domain;}

    public DnsAnalysisResult getDns () {return this.dns;}

    public void setDns(DnsAnalysisResult dns) {this.dns = dns;}

    public HttpAnalysisResult getHttp() {return this.http;}

    public void setHttp(HttpAnalysisResult http) {this.http = http;}

    public SslAnalysisResult getSsl() {return this.ssl;}

    public void setSsl(SslAnalysisResult ssl) {this.ssl = ssl;}

    public SecurityHeadersAnalysisResult getSecurityHeaders() {return this.securityHeaders;}

    public void setSecurityHeaders(SecurityHeadersAnalysisResult securityHeaders) {this.securityHeaders = securityHeaders;}
}
