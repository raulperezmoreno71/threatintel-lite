package io.github.raulperezmoreno71.threatintel.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(
        description = "Request body containing the target URL to analyze."
)
public class AnalyzeRequest {

    @Schema(
            description = "Target URL to analyze.",
            example = "https://github.com"
    )
    private String url;

    public AnalyzeRequest () {

    }

    public AnalyzeRequest (String url) {
        this.url = url;
    }

    public String getUrl () {
        return this.url;
    }

    public void setUrl (String url) {
        this.url = url;
    }
}
