package io.github.raulperezmoreno71.threatintel.support;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.model.*;
import java.util.List;
public final class AnalysisFixtures {
    public static AnalyzeResponse report(SslAnalysisResult ssl) {
        DnsAnalysisResult dns = new DnsAnalysisResult(
                List.of("93.184.216.34", "93.184.216.35")
        );

        HttpAnalysisResult http = new HttpAnalysisResult(
                200,
                "text/html",
                "nginx",
                1500L,
                "https://example.com",
                120L,
                List.of(
                        new RedirectStep(
                                "http://example.com",
                                301,
                                "https://example.com",
                                50L
                        ),
                        new RedirectStep(
                                "https://example.com",
                                200,
                                null,
                                70L
                        )
                )
        );

        SecurityHeaderResult goodHeader = new SecurityHeaderResult(
                true,
                "valid-value",
                SecurityStatus.GOOD,
                null
        );

        SecurityHeadersAnalysisResult securityHeaders =
                new SecurityHeadersAnalysisResult(
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader,
                        goodHeader
                );

        SecurityAssessmentResult securityAssessment =
                new SecurityAssessmentResult(
                        100,
                        "A",
                        6,
                        0,
                        0
                );

        return new AnalyzeResponse(
                "URL analyzed successfully",
                "https://example.com",
                "example.com",
                dns,
                http,
                ssl,
                securityHeaders,
                securityAssessment
        );
    }
}
