package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.net.URI;
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

    public AnalyzeService (
            UrlValidator urlValidator,
            DnsAnalyzer dnsAnalyzer,
            HttpAnalyzer httpAnalyzer,
            SslAnalyzer sslAnalyzer,
            SecurityHeadersAnalyzer securityHeadersAnalyzer,
            SecurityAssessmentCalculator securityAssessmentCalculator
    ) {
        this.urlValidator = urlValidator;
        this.dnsAnalyzer = dnsAnalyzer;
        this.httpAnalyzer = httpAnalyzer;
        this.sslAnalyzer = sslAnalyzer;
        this.securityHeadersAnalyzer = securityHeadersAnalyzer;
        this.securityAssessmentCalculator = securityAssessmentCalculator;
    }

    public AnalyzeResponse analyze (AnalyzeRequest request) {
        String url = request.getUrl();

        urlValidator.validate(url);

        String domain = extractDomain(url);

        DnsAnalysisResult dns = dnsAnalyzer.analyze(domain);

        HttpRedirectResult redirectResult = httpAnalyzer.followRedirects(url);

        HttpAnalysisResult http = httpAnalyzer.analyzeResponse(redirectResult);

        String finalUrl = http.getFinalUrl();
        String finalDomain = extractDomain(finalUrl);

        SslAnalysisResult ssl = sslAnalyzer.analyze(finalUrl, finalDomain);

        SecurityHeadersAnalysisResult securityHeaders = securityHeadersAnalyzer.analyze(redirectResult.getFinalResponse());

        SecurityAssessmentResult securityAssessment = securityAssessmentCalculator.calculate(securityHeaders);

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
