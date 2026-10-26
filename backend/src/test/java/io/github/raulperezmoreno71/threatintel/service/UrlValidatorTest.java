package io.github.raulperezmoreno71.threatintel.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UrlValidatorTest {

    private UrlValidator urlValidator;
    private DnsAnalyzer dnsAnalyzer;

    @BeforeEach
    void setUp() throws Exception {
        dnsAnalyzer = mock(DnsAnalyzer.class);
        when(dnsAnalyzer.resolve(anyString(), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName("8.8.8.8")});
        urlValidator = new UrlValidator(dnsAnalyzer);
    }

    @Test
    void shouldReturnAnImmutableSnapshotOfTheApprovedAddresses() throws Exception {
        InetAddress approved = InetAddress.getByName("8.8.8.8");
        InetAddress[] dnsResponse = {approved};
        when(dnsAnalyzer.resolve(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(dnsResponse);

        var target = urlValidator.validateAndResolve("https://example.com/path");
        dnsResponse[0] = InetAddress.getByName("127.0.0.1");

        assertEquals(URI.create("https://example.com/path"), target.uri());
        assertEquals(List.of(approved), target.addresses());
        assertThrows(UnsupportedOperationException.class, () -> target.addresses().clear());
        verify(dnsAnalyzer, times(1)).resolve(eq("example.com"), any(AnalysisDeadline.class));
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenUrlIsNull() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate(null)
        );

        assertEquals(
                "URL cannot be null or blank",
                exception.getMessage()
        );
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenUrlIsBlank() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate("   ")
        );

        assertEquals(
                "URL cannot be null or blank",
                exception.getMessage()
        );
    }

    @ParameterizedTest(name = "[{index}] url={0}")
    @CsvSource({
            "ftp://github.com, URL protocol must be HTTP or HTTPS",
            "https:test, URL must contain a valid host",
            "htt!s://github.com, URL has an invalid format",
            "github.com, URL protocol must be HTTP or HTTPS"
    })
    void shouldThrowIllegalArgumentExceptionForInvalidUrls (String url, String expectedMessage) {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate(url)
        );

        assertEquals(
                expectedMessage,
                exception.getMessage()
        );
    }

    @ParameterizedTest
    @CsvSource({
            "http://github.com",
            "https://github.com",
            "HTTPS://github.com",
            "http://github.com:80/path",
            "https://github.com:443/path",
            "HTTPS://github.com:443"
    })
    void shouldAcceptValidHttpAndHttpsUrls (String url) {
        assertDoesNotThrow(
                () -> urlValidator.validate(url)
        );
    }

    @ParameterizedTest
    @CsvSource({
            "http://example.com:8080",
            "https://example.com:8443",
            "http://example.com:443",
            "https://example.com:80",
            "http://example.com:0",
            "https://example.com:65536"
    })
    void shouldRejectNonStandardPorts(String url) {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate(url)
        );

        assertEquals("URL port must be 80 for HTTP or 443 for HTTPS", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255",
            "127.0.0.1", "127.255.255.255", "169.254.169.254", "172.16.0.1", "172.31.255.255",
            "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
            "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
            "::", "::1", "fc00::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1",
            "::ffff:127.0.0.1", "::ffff:192.168.1.1", "64:ff9b::7f00:1", "100::1",
            "2001::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1"
    })
    void shouldRejectNonPublicResolvedAddress(String ip) throws Exception {
        when(dnsAnalyzer.resolve(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName(ip)});

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate("https://example.com")
        );

        assertEquals("URL must resolve only to public IP addresses", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0", "172.15.255.255",
            "172.32.0.0", "198.17.255.255", "198.20.0.0", "2606:4700:4700::1111", "2001:4860:4860::8888"})
    void shouldAcceptPublicResolvedAddress(String ip) throws Exception {
        when(dnsAnalyzer.resolve(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName(ip)});

        assertDoesNotThrow(() -> urlValidator.validate("https://example.com"));
    }

    @Test
    void shouldRejectHostWithMixedPublicAndPrivateAddresses() throws Exception {
        when(dnsAnalyzer.resolve(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{
                InetAddress.getByName("8.8.8.8"), InetAddress.getByName("fd00::1")
        });

        assertThrows(IllegalArgumentException.class, () -> urlValidator.validate("https://example.com"));
    }

    @Test
    void shouldRejectHostWithoutResolvedAddresses() {
        when(dnsAnalyzer.resolve(eq("example.com"), any(AnalysisDeadline.class))).thenReturn(new InetAddress[0]);

        assertThrows(IllegalArgumentException.class, () -> urlValidator.validate("https://example.com"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://127.0.0.1", "http://127.1", "http://2130706433", "http://10.0.0.1",
            "https://[::1]", "https://[fd00::1]", "http://[::ffff:127.0.0.1]"})
    void shouldRejectLiteralPrivateIpWithoutDnsMocks(String url) {
        UrlValidator validator = new UrlValidator();

        assertThrows(IllegalArgumentException.class, () -> validator.validate(url));
    }
}
