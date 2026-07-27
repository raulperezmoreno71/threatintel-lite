package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@Schema(
        description = "Contains the DNS resolution results for the analyzed domain."
)
public class DnsAnalysisResult {
    @Schema(
            description = "List of IP addresses returned by the DNS resolution.",
            example = "[\"140.82.121.3\", \"140.82.121.4\"]"
    )
    private List<String> ips;

    public DnsAnalysisResult () {

    }

    public DnsAnalysisResult (List<String> ips) {
        this.ips = ips;
    }

    public List<String> getIps() {
        return ips;
    }

    public void setIps(List<String> ips) {
        this.ips = ips;
    }
}
