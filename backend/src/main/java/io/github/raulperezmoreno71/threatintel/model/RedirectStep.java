package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Represents a single HTTP redirection step followed during the request."
)
public class RedirectStep {

    @Schema(
            description = "URL requested during this redirection step.",
            example = "https://www.github.com/"
    )
    private String url;

    @Schema(
            description = "HTTP status code returned for this request.",
            example = "301"
    )
    private int statusCode;

    @Schema(
            description = "URL specified in the Location header for the next redirects.",
            example = "https://github.com"
    )
    private String location;

    @Schema(
            description = "Response time for this request, expressed in milliseconds.",
            example = "349"
    )
    private long responseTimeMs;

    public RedirectStep () {

    }

    public RedirectStep (String url, int statusCode, String location, long responseTimeMs) {
        this.url = url;
        this.statusCode = statusCode;
        this.location = location;
        this.responseTimeMs = responseTimeMs;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }
}
