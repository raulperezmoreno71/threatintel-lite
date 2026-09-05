package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalysisHistoryResponse;
import io.github.raulperezmoreno71.threatintel.dto.SaveAnalysisRequest;
import io.github.raulperezmoreno71.threatintel.entity.*;
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

    public void saveAnalysis(SaveAnalysisRequest request) {
        User user = getAuthenticatedUser();

        Analysis analysis = mapToEntity(request, user);

        analysisRepository.save(analysis);
    }

    private User getAuthenticatedUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        return userRepository.findByEmail(email).orElseThrow(() -> new IllegalStateException("Authenticated user not found"));
    }

    private Analysis mapToEntity(SaveAnalysisRequest request, User user) {
        DnsAnalysisResult dns = request.getDns();
        HttpAnalysisResult http = request.getHttp();
        SslAnalysisResult ssl = request.getSsl();
        SecurityHeadersAnalysisResult securityHeaders = request.getSecurityHeaders();
        SecurityAssessmentResult securityAssessment = request.getSecurityAssessment();

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
                request.getUrl(),
                request.getDomain(),
                dnsAnalysis,
                httpAnalysis,
                sslAnalysis,
                securityHeadersAnalysis,
                securityAssessmentEntity
        );

        user.addAnalysis(analysis);

        return analysis;
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
