package io.github.raulperezmoreno71.threatintel.service;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.raulperezmoreno71.threatintel.exception.SslHandshakeAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import io.github.raulperezmoreno71.threatintel.support.TlsTestSupport;
import org.junit.jupiter.api.Test;

import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.ServerSocket;
import java.net.SocketException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SslAnalyzerConnectionTest {

    @Test
    void shouldNotWaitForPeerCloseNotifyAfterSuccessfulHandshake() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        CountDownLatch release = new CountDownLatch(1);
        try (var server = (SSLServerSocket) TlsTestSupport.serverContext().getServerSocketFactory()
                .createServerSocket(0, 1, loopback);
             var executor = Executors.newFixedThreadPool(2)) {
            server.setSoTimeout(3000);
            server.setEnabledProtocols(new String[]{"TLSv1.3"});
            var peer = executor.submit(() -> {
                try (var socket = (SSLSocket) server.accept()) {
                    socket.setSoTimeout(3000);
                    socket.startHandshake();
                    // Do not read or acknowledge the client's TLS shutdown until the test permits it.
                    release.await();
                }
                return null;
            });
            try {
                URI uri = URI.create("https://rebind.invalid:" + server.getLocalPort());
                var analyzer = analyzerForLocalFixture(uri);
                var result = executor.submit(() -> analyzer.analyze(uri.toString(), "rebind.invalid",
                        AnalysisDeadline.start(Duration.ofSeconds(5))));

                assertEquals("CN=rebind.invalid", result.get(2, TimeUnit.SECONDS).getSubject());
            } finally {
                release.countDown();
            }
            peer.get(2, TimeUnit.SECONDS);
        }
    }

    @Test
    void shouldCloseRealSocketWhenTlsPeerDoesNotCompleteHandshake() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             var executor = Executors.newSingleThreadExecutor()) {
            server.setSoTimeout(3000);
            var disconnected = executor.submit(() -> {
                try (var socket = server.accept()) {
                    socket.setSoTimeout(3000);
                    try {
                        while (socket.getInputStream().read() != -1) {
                            // Accept ClientHello but never send a TLS handshake response.
                        }
                    } catch (SocketException reset) {
                        return true;
                    }
                    return true;
                }
            });
            URI uri = URI.create("https://rebind.invalid:" + server.getLocalPort());
            var analyzer = analyzerForLocalFixture(uri);

            assertThrows(AnalysisTimeoutException.class, () -> analyzer.analyze(uri.toString(), "rebind.invalid",
                    AnalysisDeadline.start(Duration.ofMillis(250))));

            assertTrue(disconnected.get(2, TimeUnit.SECONDS));
        }
    }

    @Test
    void shouldReadCertificateFromPinnedIpUsingOriginalHostname() throws Exception {
        HttpsServer server = startServer();
        try {
            URI uri = URI.create("https://rebind.invalid:" + server.getAddress().getPort());
            var analyzer = analyzerForLocalFixture(uri);

            var result = analyzer.analyze(uri.toString(), "rebind.invalid");

            assertEquals("CN=rebind.invalid", result.getSubject());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldRejectRealCertificateForDifferentHostname() throws Exception {
        HttpsServer server = startServer();
        try {
            URI uri = URI.create("https://wrong.invalid:" + server.getAddress().getPort());
            var analyzer = analyzerForLocalFixture(uri);

            assertThrows(SslHandshakeAnalysisException.class, () -> analyzer.analyze(uri.toString(), "wrong.invalid"));
        } finally {
            server.stop(0);
        }
    }

    private HttpsServer startServer() throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(TlsTestSupport.serverContext()));
        server.start();
        return server;
    }

    private SslAnalyzer analyzerForLocalFixture(URI uri) throws Exception {
        // Replace the policy boundary only for local networking tests; production rejects loopback.
        UrlValidator validator = mock(UrlValidator.class);
        when(validator.validateAndResolve(eq(uri.toString()), any(AnalysisDeadline.class))).thenReturn(
                new ValidatedUrl(uri, List.of(InetAddress.getByName("127.0.0.1")))
        );
        return new SslAnalyzer(TlsTestSupport.trustedClientContext().getSocketFactory(),
                SocketFactory.getDefault(), Clock.systemUTC(), validator);
    }
}
