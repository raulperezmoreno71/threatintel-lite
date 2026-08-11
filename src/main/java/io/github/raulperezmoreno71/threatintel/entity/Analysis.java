package io.github.raulperezmoreno71.threatintel.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
public class Analysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String message;
    private String url;
    private String domain;
    private LocalDateTime createdAt;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "dns_analysis_id")
    private DnsAnalysis dnsAnalysis;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "http_analysis_id")
    private HttpAnalysis httpAnalysis;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "ssl_analysis_id")
    private SslAnalysis sslAnalysis;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "security_headers_analysis_id")
    private SecurityHeadersAnalysis securityHeadersAnalysis;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "security_assessment_analysis_id")
    private SecurityAssessmentEntity securityAssessmentEntity;

    public Analysis() {

    }

    public Analysis(
            String message,
            String url,
            String domain,
            LocalDateTime createdAt,
            DnsAnalysis dnsAnalysis,
            HttpAnalysis httpAnalysis,
            SslAnalysis sslAnalysis,
            SecurityHeadersAnalysis securityHeadersAnalysis,
            SecurityAssessmentEntity securityAssessmentEntity
    ) {
        this.message = message;
        this.url = url;
        this.domain = domain;
        this.createdAt = createdAt;
        this.dnsAnalysis = dnsAnalysis;
        this.httpAnalysis = httpAnalysis;
        this.sslAnalysis = sslAnalysis;
        this.securityHeadersAnalysis = securityHeadersAnalysis;
        this.securityAssessmentEntity = securityAssessmentEntity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Long getId() {
        return id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public DnsAnalysis getDnsAnalysis() {
        return dnsAnalysis;
    }

    public void setDnsAnalysis(DnsAnalysis dnsAnalysis) {
        this.dnsAnalysis = dnsAnalysis;
    }

    public HttpAnalysis getHttpAnalysis() {
        return httpAnalysis;
    }

    public void setHttpAnalysis(HttpAnalysis httpAnalysis) {
        this.httpAnalysis = httpAnalysis;
    }

    public SslAnalysis getSslAnalysis() {
        return sslAnalysis;
    }

    public void setSslAnalysis(SslAnalysis sslAnalysis) {
        this.sslAnalysis = sslAnalysis;
    }

    public SecurityHeadersAnalysis getSecurityHeadersAnalysis() {
        return securityHeadersAnalysis;
    }

    public void setSecurityHeadersAnalysis(SecurityHeadersAnalysis securityHeadersAnalysis) {
        this.securityHeadersAnalysis = securityHeadersAnalysis;
    }

    public SecurityAssessmentEntity getSecurityAssessmentAnalysis() {
        return securityAssessmentEntity;
    }

    public void setSecurityAssessmentAnalysis(SecurityAssessmentEntity securityAssessmentEntity) {
        this.securityAssessmentEntity = securityAssessmentEntity;
    }
}
