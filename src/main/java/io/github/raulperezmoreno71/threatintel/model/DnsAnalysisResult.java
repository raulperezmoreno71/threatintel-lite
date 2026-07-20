package io.github.raulperezmoreno71.threatintel.model;

import java.util.List;

public class DnsAnalysisResult {
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
