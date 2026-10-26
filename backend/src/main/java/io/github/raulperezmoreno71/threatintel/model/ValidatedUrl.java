package io.github.raulperezmoreno71.threatintel.model;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;

public record ValidatedUrl(URI uri, List<InetAddress> addresses) {
    public ValidatedUrl {
        addresses = List.copyOf(addresses);
        if (addresses.isEmpty()) {
            throw new IllegalArgumentException("Validated URL must contain an IP address");
        }
    }
}
