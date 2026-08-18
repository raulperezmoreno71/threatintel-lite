package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.entity.*;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.LocalDateTime;
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
    private final AnalysisRepository analysisRepository;

    public AnalyzeService (
            UrlValidator urlValidator,
            DnsAnalyzer dnsAnalyzer,
            HttpAnalyzer httpAnalyzer,
            SslAnalyzer sslAnalyzer,
            SecurityHeadersAnalyzer securityHeadersAnalyzer,
            SecurityAssessmentCalculator securityAssessmentCalculator,
            AnalysisRepository analysisRepository
    ) {
        this.urlValidator = urlValidator;
        this.dnsAnalyzer = dnsAnalyzer;
        this.httpAnalyzer = httpAnalyzer;
        this.sslAnalyzer = sslAnalyzer;
        this.securityHeadersAnalyzer = securityHeadersAnalyzer;
        this.securityAssessmentCalculator = securityAssessmentCalculator;
        this.analysisRepository = analysisRepository;
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

        DnsAnalysis dnsAnalysis = new DnsAnalysis(dns.getIps());

        HttpAnalysis httpAnalysis = new HttpAnalysis(
                http.getStatusCode(),
                http.getContentType(),
                http.getServer(),
                http.getContentLength(),
                http.getFinalUrl(),
                http.getTotalResponseTimeMs()
        );

        List<RedirectStepEntity> redirectEntities = new ArrayList<>();

        for (RedirectStep step : http.getRedirectChain()) {
            RedirectStepEntity entity = new RedirectStepEntity(
                    step.getUrl(),
                    step.getStatusCode(),
                    step.getLocation(),
                    step.getResponseTimeMs(),
                    httpAnalysis
            );

            redirectEntities.add(entity);
        }

        httpAnalysis.setRedirectChain(redirectEntities);

        SslAnalysis sslAnalysis = null;

        if (ssl != null) {
            sslAnalysis = new SslAnalysis(
                    ssl.getIssuer(),
                    ssl.getSubject(),
                    ssl.getValidFrom(),
                    ssl.getValidUntil(),
                    ssl.getDaysUntilExpiration(),
                    ssl.getStatus(),
                    ssl.getRecommendation()
            );
        }

        SecurityHeadersAnalysis securityHeadersAnalysis = new SecurityHeadersAnalysis();

        addSecurityHeaderEntities(securityHeaders, securityHeadersAnalysis);

        SecurityAssessmentEntity securityAssessmentEntity = new SecurityAssessmentEntity(
                securityAssessment.getScore(),
                securityAssessment.getGrade(),
                securityAssessment.getGoodHeaders(),
                securityAssessment.getWarningHeaders(),
                securityAssessment.getMissingHeaders()
        );

        Analysis analysis = new Analysis(
                "URL analyzed successfully",
                url,
                domain,
                dnsAnalysis,
                httpAnalysis,
                sslAnalysis,
                securityHeadersAnalysis,
                securityAssessmentEntity
        );

        analysisRepository.save(analysis);

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
