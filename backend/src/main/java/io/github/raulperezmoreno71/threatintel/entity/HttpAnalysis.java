package io.github.raulperezmoreno71.threatintel.entity;

import jakarta.persistence.*;

import java.util.List;

@Entity
public class HttpAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer statusCode;
    private String contentType;
    private String server;
    private Long contentLength;
    private String finalUrl;
    private Long totalResponseTimeMs;

    @OneToMany(
            mappedBy = "httpAnalysis",
            cascade = CascadeType.ALL
    )
    private List<RedirectStepEntity> redirectChain;

    public HttpAnalysis() {

    }

    public HttpAnalysis(
            Integer statusCode,
            String contentType,
            String server,
            Long contentLength,
            String finalUrl,
            Long totalResponseTimeMs
            ) {
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.server = server;
        this.contentLength = contentLength;
        this.finalUrl = finalUrl;
        this.totalResponseTimeMs = totalResponseTimeMs;
    }

    public Long getId() {
        return id;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public Long getContentLength() {
        return contentLength;
    }

    public void setContentLength(Long contentLength) {
        this.contentLength = contentLength;
    }

    public String getFinalUrl() {
        return finalUrl;
    }

    public void setFinalUrl(String finalUrl) {
        this.finalUrl = finalUrl;
    }

    public Long getTotalResponseTimeMs() {
        return totalResponseTimeMs;
    }

    public void setTotalResponseTimeMs(Long totalResponseTimeMs) {
        this.totalResponseTimeMs = totalResponseTimeMs;
    }

    public List<RedirectStepEntity> getRedirectChain() {
        return redirectChain;
    }

    public void setRedirectChain(List<RedirectStepEntity> redirectChain) {
        this.redirectChain = redirectChain;
    }
}
