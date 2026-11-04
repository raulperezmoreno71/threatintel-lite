package io.github.raulperezmoreno71.threatintel.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

@Schema(
        description = "Contains the DNS resolution results for the analyzed domain."
)
public class DnsAnalysisResult {
    @Schema(
            description = "List of IP addresses returned by the DNS resolution.",
            example = "[\"140.82.121.3\", \"140.82.121.4\"]"
    )
    @NotEmpty(message = "At least one IP address is required")
    @Size(max = 64, message = "At most 64 IP addresses are allowed")
    private List<@NotBlank(message = "IP address must not be blank")
            @Size(max = 45, message = "IP address must not exceed 45 characters") String> ips;

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
