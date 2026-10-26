package io.github.raulperezmoreno71.threatintel.service;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import io.github.raulperezmoreno71.threatintel.support.TlsTestSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLException;

import static org.junit.jupiter.api.Assertions.*;

class PinnedHttpTransportTest {

    @ParameterizedTest
    @ValueSource(strings = {"Content-Length: 10000000000\r\n", "Transfer-Encoding: chunked\r\n", ""})
    void shouldReturnHeadersAndDisconnectWithoutWaitingForBody(String bodyHeaders) throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        AtomicReference<String> requestLine = new AtomicReference<>();

        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             var executor = Executors.newSingleThreadExecutor()) {
            server.setSoTimeout(5000);
            var disconnected = executor.submit(() -> {
                try (var socket = server.accept()) {
                    socket.setSoTimeout(5000);
                    var input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                    requestLine.set(input.readLine());
                    String line;
                    while ((line = input.readLine()) != null && !line.isEmpty()) {
                        // Read the complete request before replying.
                    }
                    String headers = "HTTP/1.1 200 OK\r\nX-Test: headers-only\r\n"
                            + bodyHeaders + "Connection: close\r\n\r\n";
                    socket.getOutputStream().write(headers.getBytes(StandardCharsets.US_ASCII));
                    socket.getOutputStream().flush();
                    // No body is sent. The client must close rather than wait for it.
                    try {
                        return socket.getInputStream().read() == -1;
                    } catch (SocketException reset) {
                        return true;
                    }
                }
            });
            URI uri = URI.create("http://rebind.invalid:" + server.getLocalPort() + "/report");

            var response = new PinnedHttpTransport().get(new ValidatedUrl(uri, List.of(loopback)));

            assertEquals(200, response.statusCode());
            assertEquals("headers-only", response.headers().firstValue("X-Test").orElseThrow());
            assertEquals("", response.body());
            assertTrue(disconnected.get(2, TimeUnit.SECONDS));
            assertEquals("GET /report HTTP/1.1", requestLine.get());
            if (bodyHeaders.startsWith("Content-Length")) {
                assertEquals("10000000000", response.headers().firstValue("Content-Length").orElseThrow());
            }
        }
    }

    @Test
    void shouldKeepConcurrentDnsSnapshotsIsolatedForTheSameHostname() throws Exception {
        InetAddress firstIp = InetAddress.getByName("127.0.0.1");
        InetAddress secondIp = InetAddress.getByName("127.0.0.2");
        HttpServer first = responseServer(firstIp, 0, "first");
        HttpServer second = null;
        try {
            int port = first.getAddress().getPort();
            second = responseServer(secondIp, port, "second");
            URI uri = URI.create("http://rebind.invalid:" + port);
            PinnedHttpTransport transport = new PinnedHttpTransport();

            try (var executor = Executors.newFixedThreadPool(2)) {
                var firstResult = executor.submit(() -> transport.get(new ValidatedUrl(uri, List.of(firstIp)))
                        .headers().firstValue("X-Test").orElseThrow());
                var secondResult = executor.submit(() -> transport.get(new ValidatedUrl(uri, List.of(secondIp)))
                        .headers().firstValue("X-Test").orElseThrow());

                assertEquals("first", firstResult.get(10, TimeUnit.SECONDS));
                assertEquals("second", secondResult.get(10, TimeUnit.SECONDS));
            }
        } finally {
            first.stop(0);
            if (second != null) {
                second.stop(0);
            }
        }
    }

    @Test
    void shouldConnectToLiteralIpv6Target() throws Exception {
        InetAddress loopback = InetAddress.getByName("::1");
        HttpServer server = responseServer(loopback, 0, "ipv6");
        try {
            URI uri = URI.create("http://[::1]:" + server.getAddress().getPort());

            var response = new PinnedHttpTransport().get(new ValidatedUrl(uri, List.of(loopback)));

            assertEquals("ipv6", response.headers().firstValue("X-Test").orElseThrow());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldKeepHostnameForRealHttpsCertificateVerificationAndSni() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        HttpsServer server = HttpsServer.create(new InetSocketAddress(loopback, 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(TlsTestSupport.serverContext()));
        AtomicReference<String> sni = new AtomicReference<>();
        server.createContext("/", exchange -> {
            var session = (ExtendedSSLSession) ((HttpsExchange) exchange).getSSLSession();
            session.getRequestedServerNames().stream().filter(name -> name instanceof SNIHostName)
                    .map(name -> ((SNIHostName) name).getAsciiName()).findFirst().ifPresent(sni::set);
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();

        try {
            var target = new ValidatedUrl(URI.create("https://rebind.invalid:" + server.getAddress().getPort()), List.of(loopback));

            var response = new PinnedHttpTransport(TlsTestSupport.trustedClientContext()).get(target);

            assertEquals(200, response.statusCode());
            assertEquals("rebind.invalid", sni.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldRejectTrustedCertificateForAnotherHostname() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        HttpsServer server = HttpsServer.create(new InetSocketAddress(loopback, 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(TlsTestSupport.serverContext()));
        server.start();

        try {
            var target = new ValidatedUrl(URI.create("https://wrong.invalid:" + server.getAddress().getPort()), List.of(loopback));
            var transport = new PinnedHttpTransport(TlsTestSupport.trustedClientContext());

            assertThrows(SSLException.class, () -> transport.get(target));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldRejectUntrustedCertificateWithDefaultTrustStore() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        HttpsServer server = HttpsServer.create(new InetSocketAddress(loopback, 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(TlsTestSupport.serverContext()));
        server.start();

        try {
            var target = new ValidatedUrl(URI.create("https://rebind.invalid:" + server.getAddress().getPort()), List.of(loopback));

            assertThrows(SSLException.class, () -> new PinnedHttpTransport().get(target));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldConnectToSuppliedIpAndKeepOriginalHost() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        HttpServer server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
        AtomicReference<String> host = new AtomicReference<>();
        server.createContext("/report", exchange -> {
            host.set(exchange.getRequestHeaders().getFirst("Host"));
            byte[] body = "local response".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Test", "pinned");
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();

        try {
            int port = server.getAddress().getPort();
            URI uri = URI.create("http://rebind.invalid:" + port + "/report");
            // Transport fixture only: production UrlValidator rejects loopback and this port.
            ValidatedUrl target = new ValidatedUrl(uri, List.of(loopback));

            var response = new PinnedHttpTransport().get(target);

            assertEquals(200, response.statusCode());
            assertEquals("", response.body());
            assertEquals("pinned", response.headers().firstValue("X-Test").orElseThrow());
            assertEquals("rebind.invalid:" + port, host.get());
            assertEquals(uri, response.uri());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void shouldNotFollowRedirectsInsideTransport() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        HttpServer server = HttpServer.create(new InetSocketAddress(loopback, 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://other.invalid/");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();

        try {
            var target = new ValidatedUrl(URI.create("http://rebind.invalid:" + server.getAddress().getPort()), List.of(loopback));

            var response = new PinnedHttpTransport().get(target);

            assertEquals(302, response.statusCode());
            assertEquals("http://other.invalid/", response.headers().firstValue("Location").orElseThrow());
        } finally {
            server.stop(0);
        }
    }

    private HttpServer responseServer(InetAddress address, int port, String body) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(address, port), 0);
        server.createContext("/", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Test", body);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var output = exchange.getResponseBody()) {
                output.write(bytes);
            }
        });
        server.start();
        return server;
    }
}
