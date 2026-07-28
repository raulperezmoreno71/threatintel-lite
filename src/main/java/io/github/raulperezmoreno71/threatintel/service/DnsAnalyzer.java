package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.DnsAnalysisResult;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

@Component
public class DnsAnalyzer {

    public DnsAnalysisResult analyze (String domain) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(domain);
            List<String> ips = new ArrayList<>();

            for (InetAddress address : addresses) {
                ips.add(address.getHostAddress());
            }

            return new DnsAnalysisResult(ips);

        } catch (UnknownHostException e) {
            throw new RuntimeException("Could not resolve domain IP addresses", e);
        }
    }
}
