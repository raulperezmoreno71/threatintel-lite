package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.HttpAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.HttpRedirectResult;
import io.github.raulperezmoreno71.threatintel.model.HttpRequestResult;
import io.github.raulperezmoreno71.threatintel.model.RedirectStep;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

@Component
public class HttpAnalyzer {

    private static final int MAX_REDIRECTS = 10;

    private final HttpClient httpClient;

    public HttpAnalyzer () {
        this.httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    }

    public HttpRedirectResult followRedirects(String url) {
        List<RedirectStep> redirectChain = new ArrayList<>();

        long totalResponseTimeMs = 0;
        String currentUrl = url;
        HttpResponse<String> finalResponse = null;
        int redirectCount = 0;

        while (redirectCount <= MAX_REDIRECTS) {
            HttpRequestResult requestResult = getHttpResponse(currentUrl);

            HttpResponse<String> response = requestResult.getHttpResponse();

            long responseTimeMs = requestResult.getResponseTimeMs();

            totalResponseTimeMs += responseTimeMs;
            finalResponse = response;

            int statusCode = response.statusCode();

            String location = response.headers().firstValue("Location").orElse(null);

            RedirectStep redirectStep = new RedirectStep(currentUrl, statusCode, location, responseTimeMs);

            redirectChain.add(redirectStep);

            if (!isRedirectStatus(statusCode) || location == null) {
                break;
            }

            if (redirectCount == MAX_REDIRECTS) {
                throw new RuntimeException("Maximum number of redirects exceeded");
            }

            currentUrl = URI.create(currentUrl).resolve(location).toString();

            redirectCount++;
        }

        return new HttpRedirectResult(finalResponse, redirectChain, totalResponseTimeMs);
    }

    public HttpAnalysisResult analyzeResponse (HttpRedirectResult redirectResult) {
        HttpResponse<String> response = redirectResult.getFinalResponse();

        long totalResponseTimeMs = redirectResult.getTotalResponseTimeMs();

        List<RedirectStep> redirectChain = redirectResult.getRedirectChain();

        int statusCode = response.statusCode();

        String finalUrl = redirectChain.get(redirectChain.size() -1).getUrl();

        String contentType = response.headers().firstValue("Content-Type").orElse(null);
        String server = response.headers().firstValue("Server").orElse(null);
        Long contentLength = response.headers().firstValue("Content-Length").map(Long::parseLong).orElse(null);

        return new HttpAnalysisResult(
                statusCode,
                contentType,
                server,
                contentLength,
                finalUrl,
                totalResponseTimeMs,
                redirectChain
        );
    }

    private boolean isRedirectStatus (int statusCode) {
        return statusCode == 301
                || statusCode == 302
                || statusCode == 303
                || statusCode == 307
                || statusCode == 308;
    }

    private HttpRequestResult getHttpResponse (String url) {
        try {
            HttpRequest request = HttpRequest
                    .newBuilder(new URI(url))
                    .build();

            long startTime = System.nanoTime();

            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            long endTime = System.nanoTime();

            long responseTime = (endTime - startTime) / 1_000_000;

            return new HttpRequestResult(response, responseTime);

        } catch (Exception e) {
            throw new RuntimeException("Could not send HTTP request", e);
        }
    }
}
