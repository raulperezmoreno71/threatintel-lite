package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.model.*;
import org.springframework.stereotype.Service;

import java.net.URI;

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

}
