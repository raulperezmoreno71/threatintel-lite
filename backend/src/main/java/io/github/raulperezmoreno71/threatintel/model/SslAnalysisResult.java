package io.github.raulperezmoreno71.threatintel.model;


import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

@Schema(
        description = "Contains the information and security assessment of the analyzed SSL/TLS certificate."
)
public class SslAnalysisResult {

    @Schema(
            description = "Certificate authority (CA) that issued the SSL/TLS certificate.",
            example = "CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB"
    )
    @NotBlank(message = "Certificate issuer is required")
    @Size(max = 255, message = "Certificate issuer must not exceed 255 characters")
    private String issuer;

    @Schema(
            description = "Domain or entity to which the SSL/TLS certificate was issued.",
            example = "CN=github.com"
    )
    @NotBlank(message = "Certificate subject is required")
    @Size(max = 255, message = "Certificate subject must not exceed 255 characters")
    private String subject;

    @Schema(
            description = "Date from which the SSL/TLS certificates becomes valid.",
            example = "2026-07-03"
    )
    @NotNull(message = "Certificate start date is required")
    private LocalDate validFrom;

    @Schema(
            description = "Date until which the SSL/TLS certificate remains valid.",
            example = "2026-09-30"
    )
    @NotNull(message = "Certificate expiration date is required")
    private LocalDate validUntil;

    @Schema(
            description = "Days left until expiration.",
            example = "65"
    )
    @NotNull(message = "Days until expiration are required")
    private Long daysUntilExpiration;

    @Schema(
            description = "Security assessment assigned to the SSL/TLS certificate.",
            example = "WARNING"
    )
    @NotNull(message = "Certificate status is required")
    private SslStatus status;

    @Schema(
            description = "Recommendation based on the SSL/TLS certificate assessment.",
            example = "The SSL certificate expires today and should be renewed immediately."
    )
    @Size(max = 255, message = "Certificate recommendation must not exceed 255 characters")
    private String recommendation;

    public SslAnalysisResult () {

    }

    @JsonCreator(mode = JsonCreator.Mode.DISABLED)
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

    public Long getDaysUntilExpiration() {
        return daysUntilExpiration;
    }

    public void setDaysUntilExpiration(Long daysUntilExpiration) {
        this.daysUntilExpiration = daysUntilExpiration;
    }

    public SslStatus getStatus() {return this.status;}

    public void setStatus(SslStatus status) {this.status = status;}

    public String getRecommendation() {return this.recommendation;}

    public void setRecommendation(String recommendation) {this.recommendation = recommendation;}
}
