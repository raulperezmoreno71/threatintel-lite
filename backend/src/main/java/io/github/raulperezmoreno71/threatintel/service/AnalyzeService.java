package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class AnalyzeService {

    private final UrlValidator urlValidator;
    private final DnsAnalyzer dnsAnalyzer;
    private final HttpAnalyzer httpAnalyzer;
    private final SslAnalyzer sslAnalyzer;
    private final SecurityHeadersAnalyzer securityHeadersAnalyzer;
    private final SecurityAssessmentCalculator securityAssessmentCalculator;
    private final Duration analysisTimeout;

    @Autowired
    public AnalyzeService (
            UrlValidator urlValidator,
            DnsAnalyzer dnsAnalyzer,
            HttpAnalyzer httpAnalyzer,
            SslAnalyzer sslAnalyzer,
            SecurityHeadersAnalyzer securityHeadersAnalyzer,
            SecurityAssessmentCalculator securityAssessmentCalculator,
            @Value("${app.analysis.timeout-ms:15000}") long timeoutMs
    ) {
        this.urlValidator = urlValidator;
        this.dnsAnalyzer = dnsAnalyzer;
        this.httpAnalyzer = httpAnalyzer;
        this.sslAnalyzer = sslAnalyzer;
        this.securityHeadersAnalyzer = securityHeadersAnalyzer;
        this.securityAssessmentCalculator = securityAssessmentCalculator;
        if (timeoutMs <= 0) {
            throw new IllegalArgumentException("Analysis timeout must be positive");
        }
        this.analysisTimeout = Duration.ofMillis(timeoutMs);
    }

    public AnalyzeService(UrlValidator urlValidator, DnsAnalyzer dnsAnalyzer, HttpAnalyzer httpAnalyzer,
                          SslAnalyzer sslAnalyzer, SecurityHeadersAnalyzer securityHeadersAnalyzer,
                          SecurityAssessmentCalculator securityAssessmentCalculator) {
        this(urlValidator, dnsAnalyzer, httpAnalyzer, sslAnalyzer, securityHeadersAnalyzer, securityAssessmentCalculator, 15000);
    }

    public AnalyzeResponse analyze (AnalyzeRequest request) {
        return analyze(request, AnalysisDeadline.start(analysisTimeout));
    }

    AnalyzeResponse analyze(AnalyzeRequest request, AnalysisDeadline deadline) {
        deadline.check();
        String url = request.getUrl();

        urlValidator.validate(url, deadline);
        deadline.check();

        String domain = extractDomain(url);

        DnsAnalysisResult dns = dnsAnalyzer.analyze(domain, deadline);
        deadline.check();

        HttpRedirectResult redirectResult = httpAnalyzer.followRedirects(url, deadline);
        deadline.check();

        HttpAnalysisResult http = httpAnalyzer.analyzeResponse(redirectResult);

        String finalUrl = http.getFinalUrl();
        String finalDomain = extractDomain(finalUrl);

        SslAnalysisResult ssl = sslAnalyzer.analyze(finalUrl, finalDomain, deadline);
        deadline.check();

        SecurityHeadersAnalysisResult securityHeaders = securityHeadersAnalyzer.analyze(redirectResult.getFinalResponse());

        SecurityAssessmentResult securityAssessment = securityAssessmentCalculator.calculate(securityHeaders);

        deadline.check();
        return new AnalyzeResponse(
                "URL analyzed successfully",
                url,
                domain,
                dns,
                http,
                ssl,
                securityHeaders,
                securityAssessment
        );
    }

    private String extractDomain (String url) {
        return URI.create(url).getHost();
    }

    private void addSecurityHeaderEntities(
            SecurityHeadersAnalysisResult securityHeaders,
            SecurityHeadersAnalysis securityHeadersAnalysis
    ) {
        SecurityHeaderResultEntity strictTransportSecurity = createSecurityEntity("Strict-Transport-Security", securityHeaders.getStrictTransportSecurity());
        SecurityHeaderResultEntity contentSecurityPolicy = createSecurityEntity("Content-Security-Policy", securityHeaders.getContentSecurityPolicy());
        SecurityHeaderResultEntity xFrameOptions = createSecurityEntity("X-Frame-Options", securityHeaders.getXFrameOptions());
        SecurityHeaderResultEntity xContentTypeOptions = createSecurityEntity("X-Content-Type-Options", securityHeaders.getXContentTypeOptions());
        SecurityHeaderResultEntity referrerPolicy = createSecurityEntity("Referrer-Policy", securityHeaders.getReferrerPolicy());
        SecurityHeaderResultEntity permissionsPolicy = createSecurityEntity("Permissions-Policy", securityHeaders.getPermissionsPolicy());

        securityHeadersAnalysis.addHeader(strictTransportSecurity);
        securityHeadersAnalysis.addHeader(contentSecurityPolicy);
        securityHeadersAnalysis.addHeader(xFrameOptions);
        securityHeadersAnalysis.addHeader(xContentTypeOptions);
        securityHeadersAnalysis.addHeader(referrerPolicy);
        securityHeadersAnalysis.addHeader(permissionsPolicy);
    }

    private SecurityHeaderResultEntity createSecurityEntity(String headerName, SecurityHeaderResult header) {
        return new SecurityHeaderResultEntity(
                headerName,
                header.isPresent(),
                header.getValue(),
                header.getStatus(),
                header.getRecommendation()
        );
    }

}
