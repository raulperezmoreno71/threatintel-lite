package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.SslAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslHandshakeAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslTimeoutException;
import io.github.raulperezmoreno71.threatintel.model.SslAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SslAnalyzerTest {

    private static final String TEST_URL = "https://example.com";
    private static final String TEST_HOST = "example.com";
    private static final String TEST_ISSUER = "CN=Test Issuer";
    private static final String TEST_SUBJECT = "CN=example.com";

    private SSLSocketFactory socketFactory;
    private SSLSocket sslSocket;
    private SSLSession sslSession;
    private X509Certificate certificate;
    private SslAnalyzer sslAnalyzer;
    private Clock clock;

    @BeforeEach
    void setUp() throws Exception {
        socketFactory = mock(SSLSocketFactory.class);
        sslSocket = mock(SSLSocket.class);
        sslSession = mock(SSLSession.class);
        certificate = mock(X509Certificate.class);

        clock = Clock.fixed(
                Instant.parse("2026-08-01T00:00:00Z"),
                ZoneOffset.UTC
        );

        sslAnalyzer = new SslAnalyzer(socketFactory, clock);

        when(socketFactory.createSocket()).thenReturn(sslSocket);
        when(sslSocket.getSession()).thenReturn(sslSession);
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
    }

    @Test
    void shouldReturnNullWhenUrlDoesNotUseHttps() {
        SslAnalysisResult result = sslAnalyzer.analyze("http://example.com", TEST_HOST);

        assertNull(result);

        verifyNoInteractions(socketFactory);
    }

    @ParameterizedTest(name = "[{index}] {0} days -> {1}")
    @CsvSource(value = {
            "31, GOOD, NULL",
            "30, WARNING, Renew the SSL certificate before it expires.",
            "0, WARNING, The SSL certificate expires today and should be renewed immediately.",
            "-1, CRITICAL, Replace the expired SSL certificate immediately."
            },
            nullValues = {"NULL"}
    )
    void shouldReturnCorrespondingStatusDependingOnTheExpirationDate(
            int daysUntilExpiration,
            SslStatus expectedStatus,
            String expectedRecommendation
    ) {
        X500Principal issuer = new X500Principal(TEST_ISSUER);
        X500Principal subject = new X500Principal(TEST_SUBJECT);

        LocalDate today = LocalDate.now(clock);
        LocalDate validFrom = LocalDate.of(2026, 1, 1);
        LocalDate validUntil = today.plusDays(daysUntilExpiration);

        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        when(certificate.getSubjectX500Principal()).thenReturn(subject);
        when(certificate.getNotBefore()).thenReturn(Date.from(validFrom.atStartOfDay(ZoneOffset.UTC).toInstant()));
        when(certificate.getNotAfter()).thenReturn(Date.from(validUntil.atStartOfDay(ZoneOffset.UTC).toInstant()));

        SslAnalysisResult result = sslAnalyzer.analyze(TEST_URL, TEST_HOST);

        assertEquals(expectedStatus, result.getStatus());
        assertEquals(expectedRecommendation, result.getRecommendation());
        assertEquals(issuer.getName(), result.getIssuer());
        assertEquals(subject.getName(), result.getSubject());
        assertEquals(validFrom, result.getValidFrom());
        assertEquals(validUntil, result.getValidUntil());
        assertEquals(daysUntilExpiration, result.getDaysUntilExpiration());
    }

    @Test
    void shouldThrowSslTimeoutExceptionWhenSslOperationTimesOut() throws Exception {
        SocketTimeoutException cause = new SocketTimeoutException("Connection timed out");

        doThrow(cause).when(sslSocket).connect(
                any(InetSocketAddress.class),
                anyInt()
        );

        SslTimeoutException exception = assertThrows(
                SslTimeoutException.class,
                () -> sslAnalyzer.analyze(
                        TEST_URL,
                        TEST_HOST
                )
        );

        assertEquals("SSL operation timed out", exception.getMessage());

        assertSame(cause, exception.getCause());
    }

    @Test
    void shouldThrowSslHandshakeAnalysisExceptionWhenHandshakeFails() throws Exception {
        SSLHandshakeException cause = new SSLHandshakeException("Handshake failed");

        doThrow(cause).when(sslSocket).startHandshake();

        SslHandshakeAnalysisException exception = assertThrows(
                SslHandshakeAnalysisException.class,
                () -> sslAnalyzer.analyze(
                        TEST_URL,
                        TEST_HOST
                )
        );

        assertEquals("SSL handshake failed", exception.getMessage());

        assertSame(cause, exception.getCause());
    }

    @Test
    void shouldThrowSslAnalysisExceptionWhenGettingTheCertificates() throws Exception {
        IllegalStateException cause = new IllegalStateException("Could not analyze SSL certificate");

        when(sslSession.getPeerCertificates()).thenThrow(cause);

        SslAnalysisException exception = assertThrows(
                SslAnalysisException.class,
                () -> sslAnalyzer.analyze(
                        TEST_URL,
                        TEST_HOST
                )
        );

        assertEquals("Could not analyze SSL certificate", exception.getMessage());

        assertSame(cause, exception.getCause());
    }

    @ParameterizedTest(name = "[{index}] {0} should use port {1}")
    @CsvSource({
            "https://example.com, 443",
            "https://example.com:8443, 8443"
    })
    void shouldConnectUsingExpectedPort(String url, int expectedPort) throws Exception {
        configureValidCertificate();

        sslAnalyzer.analyze(url, TEST_HOST);

        verify(sslSocket).connect(
                argThat(address -> {
                    InetSocketAddress socketAddress = (InetSocketAddress) address;

                    return socketAddress.getHostString().equals(TEST_HOST)
                            && socketAddress.getPort() == expectedPort;
                }),
                eq(5000)
        );
    }

    @Test
    void shouldCloseSslSocketAfterAnalysis() throws Exception {
        configureValidCertificate();

        sslAnalyzer.analyze(TEST_URL, TEST_HOST);

        verify(sslSocket).close();
    }

    private void configureValidCertificate() {
        X500Principal issuer = new X500Principal(TEST_ISSUER);
        X500Principal subject = new X500Principal(TEST_SUBJECT);

        LocalDate validFrom = LocalDate.of(2026, 1, 1);
        LocalDate validUntil = LocalDate.now(clock).plusDays(31);

        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        when(certificate.getSubjectX500Principal()).thenReturn(subject);
        when(certificate.getNotBefore()).thenReturn(Date.from(validFrom.atStartOfDay(ZoneOffset.UTC).toInstant()));
        when(certificate.getNotAfter()).thenReturn(Date.from(validUntil.atStartOfDay(ZoneOffset.UTC).toInstant()));
    }
}
