package io.github.raulperezmoreno71.threatintel.model;


import java.time.LocalDate;

public class SslAnalysisResult {
    private String issuer;
    private String subject;
    private LocalDate validFrom;
    private LocalDate validUntil;
    private long daysUntilExpiration;
    private SslStatus status;
    private String recommendation;

    public SslAnalysisResult () {

    }

    public SslAnalysisResult (
            String issuer,
            String subject,
            LocalDate validFrom,
            LocalDate validUntil,
            long daysUntilExpiration,
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

    public long getDaysUntilExpiration() {
        return daysUntilExpiration;
    }

    public void setDaysUntilExpiration(long daysUntilExpiration) {
        this.daysUntilExpiration = daysUntilExpiration;
    }

    public SslStatus getStatus() {return this.status;}

    public void setStatus(SslStatus status) {this.status = status;}

    public String getRecommendation() {return this.recommendation;}

    public void setRecommendation(String recommendation) {this.recommendation = recommendation;}
}
