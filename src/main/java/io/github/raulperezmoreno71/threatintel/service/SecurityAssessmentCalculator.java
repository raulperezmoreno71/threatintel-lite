package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.SecurityAssessmentResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeaderResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SecurityAssessmentCalculator {

    public SecurityAssessmentResult calculate (SecurityHeadersAnalysisResult securityHeaders) {
        SecurityHeaderResult strictTransportSecurity = securityHeaders.getStrictTransportSecurity();
        SecurityHeaderResult contentSecurityPolicy = securityHeaders.getContentSecurityPolicy();
        SecurityHeaderResult xFrameOptions = securityHeaders.getXFrameOptions();
        SecurityHeaderResult xContentTypeOptions = securityHeaders.getXContentTypeOptions();
        SecurityHeaderResult referrerPolicy = securityHeaders.getReferrerPolicy();
        SecurityHeaderResult permissionsPolicy = securityHeaders.getPermissionsPolicy();

        int score = 0;

        score += calculateHeaderScore(contentSecurityPolicy, 30);
        score += calculateHeaderScore(strictTransportSecurity, 20);
        score += calculateHeaderScore(xContentTypeOptions, 15);
        score += calculateHeaderScore(xFrameOptions, 15);
        score += calculateHeaderScore(referrerPolicy, 10);
        score += calculateHeaderScore(permissionsPolicy, 10);

        int goodHeaders = 0;
        int warningHeaders = 0;
        int missingHeaders = 0;

        List<SecurityHeaderResult> headers = List.of(
                strictTransportSecurity,
                contentSecurityPolicy,
                xFrameOptions,
                xContentTypeOptions,
                referrerPolicy,
                permissionsPolicy
        );

        for (SecurityHeaderResult header : headers) {
            switch (header.getStatus()) {
                case GOOD -> goodHeaders++;
                case WARNING -> warningHeaders++;
                case MISSING -> missingHeaders++;
            }
        }

        String grade = calculateSecurityGrade(score);

        return new SecurityAssessmentResult (
                score,
                grade,
                goodHeaders,
                warningHeaders,
                missingHeaders
        );

    }

    private int calculateHeaderScore (SecurityHeaderResult securityHeaderResult, int maximumPoints) {
        return switch (securityHeaderResult.getStatus()) {
            case GOOD -> maximumPoints;
            case WARNING -> Math.round(maximumPoints * 0.5f);
            case MISSING -> 0;
        };
    }

    private String calculateSecurityGrade (int score) {
        if (score >= 90) {return "A";}
        if (score >= 80) {return "B";}
        if (score >= 70) {return "C";}
        if (score >= 60) {return "D";}

        return "F";
    }
}
