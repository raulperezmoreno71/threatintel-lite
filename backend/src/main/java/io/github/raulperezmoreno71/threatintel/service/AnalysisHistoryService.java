package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import io.github.raulperezmoreno71.threatintel.entity.RedirectStepEntity;
import io.github.raulperezmoreno71.threatintel.entity.SecurityHeaderResultEntity;
import io.github.raulperezmoreno71.threatintel.entity.User;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisNotFoundException;
import io.github.raulperezmoreno71.threatintel.model.*;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import io.github.raulperezmoreno71.threatintel.repository.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class AnalysisHistoryService {

    private final AnalysisRepository analysisRepository;
    private final UserRepository userRepository;

    public AnalysisHistoryService(AnalysisRepository analysisRepository, UserRepository userRepository) {
        this.analysisRepository = analysisRepository;
        this.userRepository = userRepository;
    }

    public List<AnalysisHistoryResponse> getAllAnalyses() {
        User user = getAuthenticatedUser();

        List<Analysis> analyses = analysisRepository.findByUser(user);

        List<AnalysisHistoryResponse> responses = new ArrayList<>();

        for(Analysis analysis : analyses) {
            responses.add(mapToResponse(analysis));
        }

        return responses;
    }

    public AnalysisHistoryResponse getAnalysisById(Long id) {
        User user = getAuthenticatedUser();

        Analysis analysis = analysisRepository.findByIdAndUser(id, user).orElseThrow(() -> new AnalysisNotFoundException(id));

        return mapToResponse(analysis);
    }

    public void deleteAnalysisById(Long id) {
        User user = getAuthenticatedUser();

        Analysis analysis = analysisRepository.findByIdAndUser(id, user).orElseThrow(() -> new AnalysisNotFoundException(id));

        analysisRepository.delete(analysis);
    }

    private User getAuthenticatedUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        return userRepository.findByEmail(email).orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
    }

    private AnalysisHistoryResponse mapToResponse(Analysis analysis) {

        DnsAnalysisResult dns = null;

        if (analysis.getDnsAnalysis() != null) {
            dns = new DnsAnalysisResult(analysis.getDnsAnalysis().getIps());
        }

        HttpAnalysisResult http = null;

        if (analysis.getHttpAnalysis() != null) {
            List<RedirectStep> redirectChain = new ArrayList<>();

            for (RedirectStepEntity step : analysis.getHttpAnalysis().getRedirectChain()) {
                RedirectStep redirectStep = new RedirectStep(
                        step.getUrl(),
                        step.getStatusCode(),
                        step.getLocation(),
                        step.getResponseTimeMs()
                );

                redirectChain.add(redirectStep);
            }

            http = new HttpAnalysisResult(
                    analysis.getHttpAnalysis().getStatusCode(),
                    analysis.getHttpAnalysis().getContentType(),
                    analysis.getHttpAnalysis().getServer(),
                    analysis.getHttpAnalysis().getContentLength(),
                    analysis.getHttpAnalysis().getFinalUrl(),
                    analysis.getHttpAnalysis().getTotalResponseTimeMs(),
                    redirectChain
            );
        }

        SslAnalysisResult ssl = null;

        if(analysis.getSslAnalysis() != null) {
            ssl = new SslAnalysisResult(
                    analysis.getSslAnalysis().getIssuer(),
                    analysis.getSslAnalysis().getSubject(),
                    analysis.getSslAnalysis().getValidFrom(),
                    analysis.getSslAnalysis().getValidUntil(),
                    analysis.getSslAnalysis().getDaysUntilExpiration(),
                    analysis.getSslAnalysis().getStatus(),
                    analysis.getSslAnalysis().getRecommendation()
            );
        }

        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = null;

        if (analysis.getSecurityHeadersAnalysis() != null) {
            securityHeadersAnalysisResult = new SecurityHeadersAnalysisResult();

            for (SecurityHeaderResultEntity header : analysis.getSecurityHeadersAnalysis().getHeaders()) {
                SecurityHeaderResult securityHeaderResult = new SecurityHeaderResult(
                        header.isPresent(),
                        header.getValue(),
                        header.getStatus(),
                        header.getRecommendation()
                );

                switch (header.getHeaderName()) {
                    case "Strict-Transport-Security" ->
                            securityHeadersAnalysisResult.setStrictTransportSecurity(securityHeaderResult);

                    case "Content-Security-Policy" ->
                            securityHeadersAnalysisResult.setContentSecurityPolicy(securityHeaderResult);

                    case "X-Frame-Options" -> securityHeadersAnalysisResult.setXFrameOptions(securityHeaderResult);

                    case "X-Content-Type-Options" ->
                            securityHeadersAnalysisResult.setXContentTypeOptions(securityHeaderResult);

                    case "Referrer-Policy" -> securityHeadersAnalysisResult.setReferrerPolicy(securityHeaderResult);

                    case "Permissions-Policy" ->
                            securityHeadersAnalysisResult.setPermissionsPolicy(securityHeaderResult);
                }
            }
        }

        SecurityAssessmentResult securityAssessmentResult = null;

        if (analysis.getSecurityAssessmentAnalysis() != null) {
            securityAssessmentResult = new SecurityAssessmentResult(
                    analysis.getSecurityAssessmentAnalysis().getScore(),
                    analysis.getSecurityAssessmentAnalysis().getGrade(),
                    analysis.getSecurityAssessmentAnalysis().getGoodHeaders(),
                    analysis.getSecurityAssessmentAnalysis().getWarningHeaders(),
                    analysis.getSecurityAssessmentAnalysis().getMissingHeaders()
            );
        }

        return new AnalysisHistoryResponse(
                analysis.getId(),
                analysis.getMessage(),
                analysis.getUrl(),
                analysis.getDomain(),
                analysis.getCreatedAt(),
                dns,
                http,
                ssl,
                securityHeadersAnalysisResult,
                securityAssessmentResult
        );
    }
}
