package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.net.http.HttpClient;

@Service
public class AnalyzeService {

    public AnalyzeResponse analyze (AnalyzeRequest request) {
        String url = request.getUrl();

        validateUrl(url);

        String domain = extractDomain(url);
        List<String> ips = resolveIp(domain);
        HttpRequestResult requestResult = getHttpResponse(url);
        HttpAnalysisResult analysisResult = analyzeHttpResponse(requestResult);

        return new AnalyzeResponse(
                "URL analyzed successfully",
                url,
                domain,
                ips,
                analysisResult.getHttpStatusCode(),
                analysisResult.getRedirectLocation(),
                analysisResult.getContentType(),
                analysisResult.getServer(),
                analysisResult.getContentLength(),
                analysisResult.getResponseTimeMs()
        );
    }

    private void validateUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("URL cannot be null or blank");
        }

        URI uri = URI.create(url);

        if (uri.getHost() == null) {
            throw new IllegalArgumentException("URL must contain a valid host");
        }

        if (uri.getScheme() == null || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("URL protocol must be HTTP or HTTPS");
        }
    }

    private String extractDomain (String url) {
        return URI.create(url).getHost();
    }

    private List<String> resolveIp (String domain) {
        List<String> ips = new ArrayList<>();

        try {
            InetAddress[] addresses = InetAddress.getAllByName(domain);

            for (InetAddress address : addresses) {
                ips.add(address.getHostAddress());
            }

        } catch (Exception e) {
            ips.add("Could not resolve IP");
        }

        return ips;
    }

    private HttpRequestResult getHttpResponse (String url) {
        try {
            HttpClient client = HttpClient.newHttpClient();

            HttpRequest request = HttpRequest
                    .newBuilder(new URI(url))
                    .build();

            long startTime = System.nanoTime();

            HttpResponse<String> response = client.send(
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

    private HttpAnalysisResult analyzeHttpResponse (HttpRequestResult requestResult) {
        HttpResponse<String> response = requestResult.getHttpResponse();

        long responseTimeMs = requestResult.getResponseTimeMs();

        int httpStatusCode = response.statusCode();
        String redirectLocation = response.headers().firstValue("Location").orElse(null);
        String contentType = response.headers().firstValue("Content-Type").orElse(null);
        String server = response.headers().firstValue("Server").orElse(null);
        Long contentLength = response.headers().firstValue("Content-Length").map(Long::parseLong).orElse(null);

        return new HttpAnalysisResult(
                httpStatusCode,
                redirectLocation,
                contentType,
                server,
                contentLength,
                responseTimeMs
        );
    }
}
