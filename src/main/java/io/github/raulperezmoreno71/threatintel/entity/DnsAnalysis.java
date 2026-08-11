package io.github.raulperezmoreno71.threatintel.entity;

import jakarta.persistence.*;

import java.util.List;

@Entity
public class DnsAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ElementCollection
    private List<String> ips;

    public DnsAnalysis() {

    }

    public DnsAnalysis(List<String> ips) {
        this.ips = ips;
    }

    public Long getId() {
        return id;
    }

    public List<String> getIps() {
        return ips;
    }

    public void setIps(List<String> ips) {
        this.ips = ips;
    }
}
