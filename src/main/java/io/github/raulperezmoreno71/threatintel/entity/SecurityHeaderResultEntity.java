package io.github.raulperezmoreno71.threatintel.entity;

import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import jakarta.persistence.*;

@Entity
public class SecurityHeaderResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String headerName;
    private boolean present;
    private String value;

    @Enumerated(EnumType.STRING)
    private SecurityStatus status;

    private String recommendation;

    @ManyToOne
    @JoinColumn(name = "security_headers_analysis_id")
    private SecurityHeadersAnalysis securityHeadersAnalysis;

    public SecurityHeaderResultEntity() {

    }

    public SecurityHeaderResultEntity(
            String headerName,
            boolean present,
            String value,
            SecurityStatus status,
            String recommendation
    ) {
        this.headerName = headerName;
        this.present = present;
        this.value = value;
        this.status = status;
        this.recommendation = recommendation;
    }

    public Long getId() {
        return id;
    }

    public String getHeaderName() {
        return headerName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public boolean isPresent() {
        return present;
    }

    public void setPresent(boolean present) {
        this.present = present;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public SecurityStatus getStatus() {
        return status;
    }

    public void setStatus(SecurityStatus status) {
        this.status = status;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public SecurityHeadersAnalysis getSecurityHeadersAnalysis() {
        return securityHeadersAnalysis;
    }

    public void setSecurityHeadersAnalysis(SecurityHeadersAnalysis securityHeadersAnalysis) {
        this.securityHeadersAnalysis = securityHeadersAnalysis;
    }
}
