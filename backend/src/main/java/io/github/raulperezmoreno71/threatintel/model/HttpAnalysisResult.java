package io.github.raulperezmoreno71.threatintel.model;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import java.util.List;

@JsonPropertyOrder({
        "statusCode",
        "contentType",
        "server",
        "contentLength",
        "finalUrl",
        "totalResponseTimeMs",
        "redirectChain"
})

@Schema(
        description = "Contains the results of the HTTP analysis performed on the analyzed URL."
)
public class HttpAnalysisResult {
    @Schema(
            description = "The total time in milliseconds of the http request.",
            example = "623"
    )
    @NotNull(message = "Total response time is required")
    @PositiveOrZero(message = "Total response time must not be negative")
    private Long totalResponseTimeMs;

    @Schema(
            description = "The status code returned by the last server.",
            example = "200"
    )
    @NotNull(message = "HTTP status code is required")
    @Min(value = 100, message = "HTTP status code must be between 100 and 599")
    @Max(value = 599, message = "HTTP status code must be between 100 and 599")
    private Integer statusCode;

    @Schema(
            description = "Content type returned by the HTTP response.",
            example = "application/json"
    )
    @Size(max = 255, message = "Content type must not exceed 255 characters")
    private String contentType;

    @Schema(
            description = "Server identifier returned in the HTTP request.",
            example = "github.com"
    )
    @Size(max = 255, message = "Server must not exceed 255 characters")
    private String server;

    @Schema(
            description = "The total length of the message expressed in bytes.",
            example = "1260"
    )
    @PositiveOrZero(message = "Content length must not be negative")
    private Long contentLength;

    @Schema(
            description = "Final URL after following all HTTP redirects.",
            example = "https://github.com/"
    )
    @NotBlank(message = "Final URL is required")
    @Size(max = 255, message = "Final URL must not exceed 255 characters")
    private String finalUrl;

    @Schema(
            description = "List of all HTTP redirection steps followed during the request."
    )
    @NotEmpty(message = "HTTP request chain is required")
    @Size(max = 11, message = "At most 11 HTTP steps are allowed")
    private List<@NotNull(message = "HTTP step must not be null") @Valid RedirectStep> redirectChain;

    public HttpAnalysisResult ()  {

    }

    @JsonCreator(mode = JsonCreator.Mode.DISABLED)
    public HttpAnalysisResult (
            int statusCode,
            String contentType,
            String server,
            Long contentLength,
            String finalUrl,
            long totalResponseTimeMs,
            List<RedirectStep> redirectChain
    ) {
        this.totalResponseTimeMs = totalResponseTimeMs;
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.server = server;
        this.contentLength = contentLength;
        this.finalUrl = finalUrl;
        this.redirectChain = redirectChain;
    }

    public Integer getStatusCode() {
        return this.statusCode;
    }

    public void setStatusCode(Integer httpStatusCode) {
        this.statusCode = httpStatusCode;
    }

    public Long getTotalResponseTimeMs() {
        return this.totalResponseTimeMs;
    }

    public void setTotalResponseTimeMs (Long totalResponseTimeMs) {
        this.totalResponseTimeMs = totalResponseTimeMs;
    }

    public String getContentType() {
        return this.contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getServer() {
        return this.server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public Long getContentLength() {
        return this.contentLength;
    }

    public void setContentLength(Long contentLength) {
        this.contentLength = contentLength;
    }

    public List<RedirectStep> getRedirectChain() {return this.redirectChain;}

    public void setRedirectChain(List<RedirectStep> redirectChain) {this.redirectChain = redirectChain;}

    public String getFinalUrl() {return this.finalUrl;}

    public void setFinalUrl(String finalUrl) {this.finalUrl = finalUrl;}
}
