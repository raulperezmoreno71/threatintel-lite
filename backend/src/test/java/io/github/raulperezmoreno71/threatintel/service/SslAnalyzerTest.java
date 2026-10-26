package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.SslAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslHandshakeAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslTimeoutException;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
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
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIHostName;
import javax.net.SocketFactory;
import javax.security.auth.x500.X500Principal;

import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.Socket;
import java.net.SocketException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SslAnalyzerTest {

    private static final String TEST_URL = "https://example.com";
    private static final String TEST_HOST = "example.com";
    private static final String TEST_ISSUER = "CN=Test Issuer";
    private static final String TEST_SUBJECT = "CN=example.com";

    private SSLSocketFactory socketFactory;
    private SocketFactory tcpSocketFactory;
    private Socket tcpSocket;
    private SSLSocket sslSocket;
    private SSLSession sslSession;
    private X509Certificate certificate;
    private SslAnalyzer sslAnalyzer;
    private Clock clock;
    private DnsAnalyzer dnsAnalyzer;

    @BeforeEach
    void setUp() throws Exception {
        socketFactory = mock(SSLSocketFactory.class);
        tcpSocketFactory = mock(SocketFactory.class);
        tcpSocket = mock(Socket.class);
        sslSocket = mock(SSLSocket.class);
        sslSession = mock(SSLSession.class);
        certificate = mock(X509Certificate.class);

        clock = Clock.fixed(
                Instant.parse("2026-08-01T00:00:00Z"),
                ZoneOffset.UTC
        );

        dnsAnalyzer = mock(DnsAnalyzer.class);
        when(dnsAnalyzer.resolve(anyString(), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName("8.8.8.8")});
        sslAnalyzer = new SslAnalyzer(socketFactory, tcpSocketFactory, clock, new UrlValidator(dnsAnalyzer));

        when(tcpSocketFactory.createSocket()).thenReturn(tcpSocket);
        when(socketFactory.createSocket(tcpSocket, TEST_HOST, 443, true)).thenReturn(sslSocket);
        when(sslSocket.getSSLParameters()).thenReturn(new SSLParameters());
        when(sslSocket.getSession()).thenReturn(sslSession);
        when(sslSession.getPeerCertificates()).thenReturn(new Certificate[]{certificate});
    }

    @Test
    void shouldCloseTcpBeforeGracefulTlsCleanup() throws Exception {
        var tcpClosed = new java.util.concurrent.atomic.AtomicBoolean();
        doAnswer(invocation -> { tcpClosed.set(true); return null; }).when(tcpSocket).close();
        doAnswer(invocation -> {
            assertTrue(tcpClosed.get(), "TCP must already be closed so TLS cleanup cannot wait for close_notify");
            return null;
        }).when(sslSocket).close();
        configureValidCertificate();

        sslAnalyzer.analyze(TEST_URL, TEST_HOST);
    }

    @Test
    void shouldCloseTlsSocketWhenSharedDeadlineExpiresDuringHandshake() throws Exception {
        CountDownLatch closed = new CountDownLatch(1);
        doAnswer(invocation -> { closed.countDown(); return null; }).when(tcpSocket).close();
        doAnswer(invocation -> {
            assertTrue(closed.await(2, TimeUnit.SECONDS), "Deadline must close the stalled TLS socket");
            throw new SocketException("Socket closed");
        }).when(sslSocket).startHandshake();

        assertThrows(AnalysisTimeoutException.class, () -> sslAnalyzer.analyze(TEST_URL, TEST_HOST,
                AnalysisDeadline.start(Duration.ofMillis(250))));
    }

    @Test
    void shouldNotOpenSocketAfterBudgetExpires() {
        java.util.concurrent.atomic.AtomicLong ticker = new java.util.concurrent.atomic.AtomicLong();
        AnalysisDeadline deadline = new AnalysisDeadline(Duration.ofSeconds(1), ticker::get);
        ticker.set(Duration.ofSeconds(1).toNanos());

        assertThrows(AnalysisTimeoutException.class, () -> sslAnalyzer.analyze(TEST_URL, TEST_HOST, deadline));

        verifyNoInteractions(socketFactory, tcpSocketFactory);
    }

    @Test
    void shouldConnectOnlyToTheApprovedAddressWhenDnsChanges() throws Exception {
        InetAddress approved = InetAddress.getByName("8.8.8.8");
        when(dnsAnalyzer.resolve(eq(TEST_HOST), any(AnalysisDeadline.class))).thenReturn(
                new InetAddress[]{approved},
                new InetAddress[]{InetAddress.getByName("127.0.0.1")}
        );
        configureValidCertificate();

        sslAnalyzer.analyze(TEST_URL, TEST_HOST);

        verify(tcpSocket).connect(argThat(address -> {
            InetSocketAddress target = (InetSocketAddress) address;
            return !target.isUnresolved() && approved.equals(target.getAddress());
        }), eq(5000));
        verify(dnsAnalyzer, times(1)).resolve(eq(TEST_HOST), any(AnalysisDeadline.class));
    }

    @Test
    void shouldEnableHttpsEndpointIdentification() {
        configureValidCertificate();

        sslAnalyzer.analyze(TEST_URL, TEST_HOST);

        verify(sslSocket).setSSLParameters(argThat(parameters ->
                "HTTPS".equals(parameters.getEndpointIdentificationAlgorithm())
                        && parameters.getServerNames().equals(java.util.List.of(new SNIHostName(TEST_HOST)))));
    }

    @Test
    void shouldCloseTcpSocketWhenTlsLayerCannotBeCreated() throws Exception {
        when(socketFactory.createSocket(tcpSocket, TEST_HOST, 443, true)).thenThrow(new IOException("TLS layer failed"));

        assertThrows(SslAnalysisException.class, () -> sslAnalyzer.analyze(TEST_URL, TEST_HOST));

        verify(tcpSocket).close();
    }

    @Test
    void shouldTryOnlyApprovedAddressesWhenFirstConnectionFails() throws Exception {
        Socket secondSocket = mock(Socket.class);
        when(tcpSocketFactory.createSocket()).thenReturn(tcpSocket, secondSocket);
        doThrow(new IOException("First address unreachable")).when(tcpSocket).connect(any(), anyInt());
        when(socketFactory.createSocket(secondSocket, TEST_HOST, 443, true)).thenReturn(sslSocket);
        when(dnsAnalyzer.resolve(eq(TEST_HOST), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{
                InetAddress.getByName("8.8.8.8"), InetAddress.getByName("1.1.1.1")
        });
        configureValidCertificate();

        sslAnalyzer.analyze(TEST_URL, TEST_HOST);

        verify(tcpSocket).close();
        verify(secondSocket).connect(argThat(address ->
                ((InetSocketAddress) address).getAddress().getHostAddress().equals("1.1.1.1")), eq(5000));
        verify(dnsAnalyzer, times(1)).resolve(eq(TEST_HOST), any(AnalysisDeadline.class));
    }

    @Test
    void shouldRejectPrivateDestinationBeforeOpeningSslSocket() throws Exception {
        when(dnsAnalyzer.resolve(eq(TEST_HOST), any(AnalysisDeadline.class))).thenReturn(new InetAddress[]{InetAddress.getByName("10.0.0.1")});

        assertThrows(IllegalArgumentException.class, () -> sslAnalyzer.analyze(TEST_URL, TEST_HOST));

        verifyNoInteractions(socketFactory);
    }

    @Test
    void shouldRejectHostDifferentFromValidatedUrl() {
        assertThrows(IllegalArgumentException.class, () -> sslAnalyzer.analyze(TEST_URL, "127.0.0.1"));

        verifyNoInteractions(socketFactory);
    }

    @Test
    void shouldRejectNonStandardPortBeforeOpeningSslSocket() {
        assertThrows(IllegalArgumentException.class, () -> sslAnalyzer.analyze("https://example.com:8443", TEST_HOST));

        verifyNoInteractions(socketFactory);
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

        doThrow(cause).when(tcpSocket).connect(
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
        verify(sslSocket).close();
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
            "https://example.com:443, 443"
    })
    void shouldConnectUsingExpectedPort(String url, int expectedPort) throws Exception {
        configureValidCertificate();

        sslAnalyzer.analyze(url, TEST_HOST);

        verify(tcpSocket).connect(
                argThat(address -> {
                    InetSocketAddress socketAddress = (InetSocketAddress) address;

                    return socketAddress.getAddress().getHostAddress().equals("8.8.8.8")
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
