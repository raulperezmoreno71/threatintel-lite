package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import org.springframework.stereotype.Component;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;

@Component
public class UrlValidator {

    private static final List<IpAddressMatcher> BLOCKED_RANGES = List.of(
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
            "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
            "203.0.113.0/24", "224.0.0.0/3",
            "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"
    ).stream().map(IpAddressMatcher::new).toList();

    private static final IpAddressMatcher IPV6_GLOBAL_UNICAST = new IpAddressMatcher("2000::/3");

    private final DnsAnalyzer dnsAnalyzer;

    public UrlValidator(DnsAnalyzer dnsAnalyzer) {
        this.dnsAnalyzer = dnsAnalyzer;
    }

    public UrlValidator() {
        this(new DnsAnalyzer());
    }

    public void validate (String url) {
        validate(url, AnalysisDeadline.startDefault());
    }

    public void validate(String url, AnalysisDeadline deadline) {
        validateAndResolve(url, deadline);
    }

    public ValidatedUrl validateAndResolve(String url) {
        return validateAndResolve(url, AnalysisDeadline.startDefault());
    }

    public ValidatedUrl validateAndResolve(String url, AnalysisDeadline deadline) {
        deadline.check();
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("URL cannot be null or blank");
        }

        URI uri;

        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("URL has an invalid format", e);
        }

        if (uri.getScheme() == null || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("URL protocol must be HTTP or HTTPS");
        }

        if (uri.getHost() == null) {
            throw new IllegalArgumentException("URL must contain a valid host");
        }

        int port = uri.getPort();
        int standardPort = "http".equalsIgnoreCase(uri.getScheme()) ? 80 : 443;

        if (port != -1 && port != standardPort) {
            throw new IllegalArgumentException("URL port must be 80 for HTTP or 443 for HTTPS");
        }

        InetAddress[] addresses = dnsAnalyzer.resolve(uri.getHost(), deadline);

        if (addresses.length == 0) {
            throw new IllegalArgumentException("URL must resolve only to public IP addresses");
        }

        for (InetAddress address : addresses) {
            deadline.check();
            if (!isPublicAddress(address)) {
                throw new IllegalArgumentException("URL must resolve only to public IP addresses");
            }
        }

        return new ValidatedUrl(uri, List.of(addresses));
    }

    private boolean isPublicAddress(InetAddress address) {
        String ip = address.getHostAddress();

        if (address.getAddress().length == 16 && !IPV6_GLOBAL_UNICAST.matches(ip)) {
            return false;
        }

        return BLOCKED_RANGES.stream().noneMatch(range -> range.matches(ip));
    }
}
