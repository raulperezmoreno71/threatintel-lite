package io.github.raulperezmoreno71.threatintel.entity;

import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import jakarta.persistence.*;

import java.time.LocalDate;

@Entity
public class SslAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String issuer;
    private String subject;
    private LocalDate validFrom;
    private LocalDate validUntil;
    private Long daysUntilExpiration;

    @Enumerated(EnumType.STRING)
    private SslStatus status;

    private String recommendation;

    public SslAnalysis() {

    }

    public SslAnalysis(
            String issuer,
            String subject,
            LocalDate validFrom,
            LocalDate validUntil,
            Long daysUntilExpiration,
            SslStatus status,
            String recommendation
    ) {
        this.issuer = issuer;
        this.subject = subject;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
        this.daysUntilExpiration = daysUntilExpiration;
        this.status = status;
        this.recommendation = recommendation;
    }

    public Long getId() {
        return id;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public LocalDate getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(LocalDate validFrom) {
        this.validFrom = validFrom;
    }

    public LocalDate getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(LocalDate validUntil) {
        this.validUntil = validUntil;
    }

    public Long getDaysUntilExpiration() {
        return daysUntilExpiration;
    }

    public void setDaysUntilExpiration(Long daysUntilExpiration) {
        this.daysUntilExpiration = daysUntilExpiration;
    }

    public SslStatus getStatus() {
        return status;
    }

    public void setStatus(SslStatus status) {
        this.status = status;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }
}
