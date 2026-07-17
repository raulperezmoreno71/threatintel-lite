package io.github.raulperezmoreno71.threatintel.service;

import java.net.http.HttpResponse;

public class HttpRequestResult {
    private HttpResponse<String> httpResponse;
    private long responseTimeMs;

    public HttpRequestResult() {

    }

    public HttpRequestResult(HttpResponse<String> httpResponse, long responseTimeMs) {
        this.httpResponse = httpResponse;
        this.responseTimeMs = responseTimeMs;
    }

    public HttpResponse<String> getHttpResponse () {return this.httpResponse;}

    public void setHttpResponse (HttpResponse<String> httpResponse) {this.httpResponse = httpResponse;}

    public long getResponseTimeMs () {return this.responseTimeMs;}

    public void setResponseTimeMs (long responseTimeMs) {this.responseTimeMs = responseTimeMs;}
}
