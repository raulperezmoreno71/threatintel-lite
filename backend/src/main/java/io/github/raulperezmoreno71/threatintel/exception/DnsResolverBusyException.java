package io.github.raulperezmoreno71.threatintel.exception;

public class DnsResolverBusyException extends RuntimeException {
    public DnsResolverBusyException() {
        super("DNS resolver is busy; try again later");
    }
}
