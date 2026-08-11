package io.github.raulperezmoreno71.threatintel.entity;

import jakarta.persistence.*;

import java.util.ArrayList;
import java.util.List;

@Entity
public class SecurityHeadersAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToMany(
            mappedBy = "securityHeadersAnalysis",
            cascade = CascadeType.ALL
    )
    private List<SecurityHeaderResultEntity> headers = new ArrayList<>();

    public SecurityHeadersAnalysis() {

    }

    public SecurityHeadersAnalysis(List<SecurityHeaderResultEntity> headers) {
        this.headers = headers;
    }

    public Long getId() {
        return id;
    }

    public List<SecurityHeaderResultEntity> getHeaders() {
        return headers;
    }

    public void setHeaders(List<SecurityHeaderResultEntity> headers) {
        this.headers = headers;
    }

    public void addHeader(SecurityHeaderResultEntity header) {
        headers.add(header);
        header.setSecurityHeadersAnalysis(this);
    }
}
