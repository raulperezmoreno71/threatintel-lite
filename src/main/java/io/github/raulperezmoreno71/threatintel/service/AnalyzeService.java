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
import java.util.Locale;

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

        SecurityHeaderResult strictTransportSecurity = analyzeStrictTransportSecurity(response);
        SecurityHeaderResult contentSecurityPolicy = analyzeContentSecurityPolicy(response);
        SecurityHeaderResult xFrameOptions = analyzeXFrameOptions(response);
        SecurityHeaderResult xContentTypeOptions = analyzeXContentTypeOptions(response);
        SecurityHeaderResult referrerPolicy = analyzeReferrerPolicy(response);
        SecurityHeaderResult permissionsPolicy = analyzePermissionsPolicy(response);
        return new SecurityHeadersAnalysisResult(
                strictTransportSecurity,
                contentSecurityPolicy,
                xFrameOptions,
                xContentTypeOptions,
                referrerPolicy,
                permissionsPolicy
        );
    }

    private SecurityHeaderResult analyzeXContentTypeOptions (HttpResponse<String> response) {
        String value = response.headers().firstValue("X-Content-Type-Options").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add X-Content-Type-Options with the value 'nosniff'."
            );
        }

        if ("nosniff".equalsIgnoreCase(value.trim())) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.GOOD,
                    null
            );
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Set X-Content-Type-Options to 'nosniff'."
        );
    }

    private SecurityHeaderResult analyzeXFrameOptions (HttpResponse<String> response) {
        String value = response.headers().firstValue("X-Frame-Options").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add the X-Frame-Options header with the value 'DENY' or 'SAMEORIGIN' to protect against clickjacking."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        if ("deny".equals(normalizedValue) || "sameorigin".equals(normalizedValue)) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.GOOD,
                    null
            );
        }

        if (normalizedValue.startsWith("allow-from")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "ALLOW-FROM is obsolete. Consider using 'DENY' or 'SAMEORIGIN'."
            );
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Use 'DENY' or 'SAMEORIGIN' as the X-Frame-Options value."
        );
    }

    private SecurityHeaderResult analyzeStrictTransportSecurity (HttpResponse<String> response) {
        String value = response.headers().firstValue("Strict-Transport-Security").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add the Strict-Transport-Security header with a max-age of at least 31536000 seconds."
            );
        }

        String[] directives = value.split(";");

        for (String directive : directives) {

            String normalizeValue = directive.trim().toLowerCase(Locale.ROOT);

            if (normalizeValue.startsWith("max-age=")){

                try {
                    long maxAge = Long.parseLong(normalizeValue.substring(8).trim());

                    if (maxAge < 0) {
                        return new SecurityHeaderResult(
                                true,
                                value,
                                SecurityStatus.WARNING,
                                "Set max-age to a valid non-negative number of seconds."
                        );
                    }

                    if (maxAge == 0) {
                        return new SecurityHeaderResult(
                                true,
                                value,
                                SecurityStatus.WARNING,
                                "HSTS is disabled. Set max-age to at least 31536000 seconds."
                        );
                    }

                    if (maxAge < 31_536_000) {
                        return new SecurityHeaderResult(
                                true,
                                value,
                                SecurityStatus.WARNING,
                                "Increase max-age to at least 31536000 seconds."
                        );
                    }

                    return new SecurityHeaderResult(
                            true,
                            value,
                            SecurityStatus.GOOD,
                            null
                    );
                } catch (NumberFormatException e) {
                    return new SecurityHeaderResult(
                            true,
                            value,
                            SecurityStatus.WARNING,
                            "Set max-age to a valid non-negative number of seconds."
                    );
                }
            }
        }
        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Add a valid max-age directive to the Strict-Transport-Security header."
        );
    }

    private SecurityHeaderResult analyzeReferrerPolicy (HttpResponse<String> response) {
        String value = response.headers().firstValue("Referrer-Policy").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add the Referrer-Policy header to control how much referrer information is shared."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        String[] policies = normalizedValue.split(",");

        String effectivePolicy = null;

        for (int i = policies.length - 1; i >= 0; i--) {
            String policy = policies[i].trim();

            if (isValidReferrerPolicy(policy)) {
                effectivePolicy = policy;
                break;
            }
        }

        if (effectivePolicy == null) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Use a valid Referrer-Policy value."
            );
        }

        switch (effectivePolicy) {
            case "strict-origin-when-cross-origin", "strict-origin", "same-origin", "no-referrer" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.GOOD,
                        null
                );
            }
            case "origin", "origin-when-cross-origin" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.WARNING,
                        "Consider using 'strict-origin-when-cross-origin' for better privacy protection."
                );
            }
            case "unsafe-url" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.WARNING,
                        "Avoid using 'unsafe-url' as it exposes the full referrer URL to other origins."
                );
            }
            case "no-referrer-when-downgrade" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.WARNING,
                        "Consider using 'strict-origin-when-cross-origin' instead."
                );
            }
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Use a valid Referrer-Policy value."
        );
    }

    private boolean isValidReferrerPolicy (String policy) {
        return switch (policy) {
            case "no-referrer",
                 "no-referrer-when-downgrade",
                 "origin",
                 "origin-when-cross-origin",
                 "same-origin",
                 "strict-origin",
                 "strict-origin-when-cross-origin",
                 "unsafe-url" -> true;

            default -> false;
        };
    }

    private SecurityHeaderResult analyzePermissionsPolicy (HttpResponse<String> response) {
        String value = response.headers().firstValue("Permissions-Policy").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add a Permissions-Policy header to restrict access to unnecessary browser features."
            );
        }

        if (value.isBlank()) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Configure Permissions-Policy with explicit restrictions for unused browser features."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        if (normalizedValue.contains("'none'")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Use the current Permissions-Policy syntax, such as camera=() and microphone=()."
            );
        }

        if (!normalizedValue.contains("=") || !normalizedValue.contains("(") || !normalizedValue.contains(")")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Use valid Permissions-Policy directives in the form feature=(allowlist)."
            );
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.GOOD,
                null
        );
    }

    private SecurityHeaderResult analyzeContentSecurityPolicy (HttpResponse<String> response) {
        String value = response.headers().firstValue("Content-Security-Policy").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add a Content-Security-Policy header to restrict the sources from which content can be loaded and executed."
            );
        }

        if (value.isBlank()) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Configure Content-Security-Policy with explicit resource restrictions."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        if (normalizedValue.contains("'unsafe-eval'")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Avoid using 'unsafe-eval' because it allows dynamic JavaScript code execution."
            );
        }

        if (normalizedValue.contains("'unsafe-inline'")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Avoid using 'unsafe-inline'. Use nonces or hashes for required inline scripts and styles."
            );
        }

        if (!normalizedValue.contains("default-src") && !normalizedValue.contains("script-src")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Add a 'default-src' or 'script-src' directive to restrict JavaScript sources."
            );
        }

        String[] directives = normalizedValue.split(";");

        for (String directive : directives) {
            String normalizedDirective = directive.trim();

            if (normalizedDirective.startsWith("default-src ") || normalizedDirective.startsWith("script-src ")) {
                String sources = normalizedDirective.substring(normalizedDirective.indexOf(' ') + 1).trim();

                if ("*".equals(sources) || sources.startsWith("* ")) {
                    return new SecurityHeaderResult(
                            true,
                            value,
                            SecurityStatus.WARNING,
                            "Avoid wildcard sources in 'default-src' and 'script-src'. Restrict resources to trusted origins."
                    );
                }
            }
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.GOOD,
                null
        );
    }


}
