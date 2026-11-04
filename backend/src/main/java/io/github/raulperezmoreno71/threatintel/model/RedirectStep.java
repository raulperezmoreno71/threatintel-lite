package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.*;

@Schema(
        description = "Represents a single HTTP redirection step followed during the request."
)
public class RedirectStep {

    @Schema(
            description = "URL requested during this redirection step.",
            example = "https://www.github.com/"
    )
    @NotBlank(message = "Step URL is required")
    @Size(max = 255, message = "Step URL must not exceed 255 characters")
    private String url;

    @Schema(
            description = "HTTP status code returned for this request.",
            example = "301"
    )
    @NotNull(message = "HTTP status code is required")
    @Min(value = 100, message = "HTTP status code must be between 100 and 599")
    @Max(value = 599, message = "HTTP status code must be between 100 and 599")
    private Integer statusCode;

    @Schema(
            description = "URL specified in the Location header for the next redirects.",
            example = "https://github.com"
    )
    @Size(max = 255, message = "Redirect location must not exceed 255 characters")
    private String location;

    @Schema(
            description = "Response time for this request, expressed in milliseconds.",
            example = "349"
    )
    @NotNull(message = "Response time is required")
    @PositiveOrZero(message = "Response time must not be negative")
    private Long responseTimeMs;

    public RedirectStep () {

    }

    @JsonCreator(mode = JsonCreator.Mode.DISABLED)
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
}
