package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.model.*;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.net.http.HttpClient;

@Service
public class AnalyzeService {

    private static final int SSL_TIMEOUT_MS = 5000;
    private static final int MAX_REDIRECTS = 10;

    public AnalyzeResponse analyze (AnalyzeRequest request) {
        String url = request.getUrl();

        validateUrl(url);

        String domain = extractDomain(url);

        DnsAnalysisResult dns = analyzeDns(domain);

        HttpRedirectResult redirectResult = followRedirects(url);

        HttpAnalysisResult http = analyzeHttpResponse(redirectResult);

        String finalUrl = http.getFinalUrl();
        String finalDomain = extractDomain(finalUrl);

        SslAnalysisResult ssl = analyzeSslCertificate(finalUrl, finalDomain);

        SecurityHeadersAnalysisResult securityHeaders = analyzeSecurityHeaders(redirectResult.getFinalResponse());

        return new AnalyzeResponse(
                "URL analyzed successfully",
                url,
                domain,
                dns,
                http,
                ssl,
                securityHeaders
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

    private DnsAnalysisResult analyzeDns (String domain) {
        List<String> ips = new ArrayList<>();

        try {
            InetAddress[] addresses = InetAddress.getAllByName(domain);

            for (InetAddress address : addresses) {
                ips.add(address.getHostAddress());
            }

        } catch (Exception e) {
            ips.add("Could not resolve IP");
        }

        return new DnsAnalysisResult(ips);
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

    private HttpAnalysisResult analyzeHttpResponse (HttpRedirectResult redirectResult) {
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

    private HttpRedirectResult followRedirects (String url) {
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

    private boolean isRedirectStatus (int statusCode) {
        return statusCode == 301
                || statusCode == 302
                || statusCode == 303
                || statusCode == 307
                || statusCode == 308;
    }

    private SslAnalysisResult analyzeSslCertificate (String url, String host) {
        URI uri = URI.create(url);
        int port;

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            return null;
        }

        if (uri.getPort() == -1) {
            port = 443;
        } else {
            port = uri.getPort();
        }

        SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        try (SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket()) {

            sslSocket.connect(new InetSocketAddress(host, port), SSL_TIMEOUT_MS);

            sslSocket.setSoTimeout(SSL_TIMEOUT_MS);

            sslSocket.startHandshake();

            SSLSession session = sslSocket.getSession();

            Certificate[] certificates = session.getPeerCertificates();

            X509Certificate certificate = (X509Certificate) certificates[0];

            String issuer = certificate.getIssuerX500Principal().getName();

            String subject = certificate.getSubjectX500Principal().getName();

            LocalDate validFrom = certificate.getNotBefore().toInstant().atZone(ZoneOffset.UTC).toLocalDate();

            LocalDate validUntil = certificate.getNotAfter().toInstant().atZone(ZoneOffset.UTC).toLocalDate();

            long daysUntilExpiration = ChronoUnit.DAYS.between(LocalDate.now(ZoneOffset.UTC), validUntil);

            return new SslAnalysisResult(
                    issuer,
                    subject,
                    validFrom,
                    validUntil,
                    daysUntilExpiration
            );

        } catch (SocketTimeoutException e) {

            throw new RuntimeException("SSL operation timed out", e);

        } catch (SSLHandshakeException e) {

            throw new RuntimeException("SSL handshake failed", e);

        } catch (Exception e) {

            throw new RuntimeException("Could not analyze SSL certificate", e);

        }
    }

    private SecurityHeadersAnalysisResult analyzeSecurityHeaders (HttpResponse<String> response) {

        SecurityHeaderResult strictTransportSecurity = analyzeSecurityHeader(response, "Strict-Transport-Security");
        SecurityHeaderResult contentSecurityPolicy = analyzeSecurityHeader(response, "Content-Security-Policy");
        SecurityHeaderResult xFrameOptions = analyzeSecurityHeader(response, "X-Frame-Options");
        SecurityHeaderResult xContentTypeOptions = analyzeSecurityHeader(response, "X-Content-Type-Options");
        SecurityHeaderResult referrerPolicy = analyzeSecurityHeader(response, "Referrer-Policy");
        SecurityHeaderResult permissionsPolicy = analyzeSecurityHeader(response, "Permissions-Policy");

        return new SecurityHeadersAnalysisResult(
                strictTransportSecurity,
                contentSecurityPolicy,
                xFrameOptions,
                xContentTypeOptions,
                referrerPolicy,
                permissionsPolicy
        );
    }

    private SecurityHeaderResult analyzeSecurityHeader (HttpResponse<String> response, String headerName) {

        String value = response.headers().firstValue(headerName).orElse(null);

        return new SecurityHeaderResult(value != null, value);
    }
}
