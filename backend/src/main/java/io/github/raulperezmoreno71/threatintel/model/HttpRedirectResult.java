package io.github.raulperezmoreno71.threatintel.model;

import java.net.http.HttpResponse;
import java.util.List;

public class HttpRedirectResult {
    private HttpResponse<String> finalResponse;
    private List<RedirectStep> redirectChain;
    private long totalResponseTimeMs;

    public HttpRedirectResult () {

    }

    public HttpRedirectResult (HttpResponse<String> finalResponse, List<RedirectStep> redirectChain, long totalResponseTimeMs) {
        this.finalResponse = finalResponse;
        this.redirectChain = redirectChain;
        this.totalResponseTimeMs = totalResponseTimeMs;
    }

    public HttpResponse<String> getFinalResponse() {
        return finalResponse;
    }

    public void setFinalResponse(HttpResponse<String> finalResponse) {
        this.finalResponse = finalResponse;
    }

    public List<RedirectStep> getRedirectChain() {
        return redirectChain;
    }

    public void setRedirectChain(List<RedirectStep> redirectChain) {
        this.redirectChain = redirectChain;
    }

    public long getTotalResponseTimeMs() {
        return totalResponseTimeMs;
    }

    public void setTotalResponseTimeMs(long totalResponseTimeMs) {
        this.totalResponseTimeMs = totalResponseTimeMs;
    }
}
