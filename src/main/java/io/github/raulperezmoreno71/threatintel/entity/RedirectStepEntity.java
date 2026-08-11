package io.github.raulperezmoreno71.threatintel.entity;

import jakarta.persistence.*;

@Entity
public class RedirectStepEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String url;
    private Integer statusCode;
    private String location;
    private Long responseTimeMs;

    @ManyToOne
    @JoinColumn(name = "http_analysis_id")
    private HttpAnalysis httpAnalysis;

    public RedirectStepEntity() {

    }

    public RedirectStepEntity(String url, Integer statusCode, String location, Long responseTimeMs, HttpAnalysis httpAnalysis) {
        this.url = url;
        this.statusCode = statusCode;
        this.location = location;
        this.responseTimeMs = responseTimeMs;
        this.httpAnalysis = httpAnalysis;
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

    public Integer getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public Long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(Long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public HttpAnalysis getHttpAnalysis() {
        return httpAnalysis;
    }

    public void setHttpAnalysis(HttpAnalysis httpAnalysis) {
        this.httpAnalysis = httpAnalysis;
    }
}
