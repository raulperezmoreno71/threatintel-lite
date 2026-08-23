package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.DnsResolutionException;
import io.github.raulperezmoreno71.threatintel.model.DnsAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.*;

class DnsAnalyzerTest {

    private DnsAnalyzer dnsAnalyzer;

    @BeforeEach
    void setUp() {
        dnsAnalyzer = new DnsAnalyzer();
    }

    @Test
    void shouldReturnIpAddressesWhenDomainCanBeResolved() {
        DnsAnalysisResult result = dnsAnalyzer.analyze("localhost");

        assertNotNull(result);
        assertNotNull(result.getIps());
        assertFalse(result.getIps().isEmpty());
    }

    @Test
    void shouldThrowExceptionWhenDomainCannotBeResolved() {
        DnsResolutionException exception = assertThrows(
                DnsResolutionException.class,
                () -> dnsAnalyzer.analyze("domain-that-does-not-exist.invalid")
        );

        assertEquals(
                "Could not resolve domain IP addresses",
                exception.getMessage()
        );

        assertInstanceOf(
                UnknownHostException.class,
                exception.getCause()
        );
    }
}
