package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.SslAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslHandshakeAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslTimeoutException;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import io.github.raulperezmoreno71.threatintel.model.SslAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SNIHostName;
import javax.net.SocketFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Component
public class SslAnalyzer {

    private static final int SSL_TIMEOUT_MS = 5000;

    private final SSLSocketFactory socketFactory;
    private final Clock clock;
    private final UrlValidator urlValidator;
    private final SocketFactory tcpSocketFactory;

    public SslAnalyzer(SSLSocketFactory socketFactory, SocketFactory tcpSocketFactory, Clock clock, UrlValidator urlValidator) {
        this.socketFactory = socketFactory;
        this.tcpSocketFactory = tcpSocketFactory;
        this.clock = clock;
        this.urlValidator = urlValidator;
    }

    public SslAnalyzer() {
        this(
                (SSLSocketFactory) SSLSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                Clock.systemUTC(),
                new UrlValidator()
        );
    }

    public SslAnalysisResult analyze (String url, String host) {
        return analyze(url, host, AnalysisDeadline.startDefault());
    }

    public SslAnalysisResult analyze(String url, String host, AnalysisDeadline deadline) {
        deadline.check();
        URI uri = URI.create(url);
        int port;

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            return null;
        }

        ValidatedUrl target = urlValidator.validateAndResolve(url, deadline);

        if (!uri.getHost().equalsIgnoreCase(host)) {
            throw new IllegalArgumentException("SSL host must match the validated URL host");
        }

        if (uri.getPort() == -1) {
            port = 443;
        } else {
            port = uri.getPort();
        }

        String peerHost = host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
        try (PinnedTlsConnection connection = openPinnedSocket(target, peerHost, port, deadline);
             var cancellation = deadline.abortOnTimeout(() -> closeSocket(connection.tcp()))) {
            SSLSocket sslSocket = connection.tls();

            sslSocket.setSoTimeout(deadline.timeoutMillis(SSL_TIMEOUT_MS));

            var parameters = sslSocket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            parameters.setServerNames(peerHost.contains(":") || peerHost.matches("[0-9.]+")
                    ? List.of() : List.of(new SNIHostName(peerHost)));
            sslSocket.setSSLParameters(parameters);

            sslSocket.startHandshake();
            deadline.check();

            SSLSession session = sslSocket.getSession();

            Certificate[] certificates = session.getPeerCertificates();

            X509Certificate certificate = (X509Certificate) certificates[0];

            String issuer = certificate.getIssuerX500Principal().getName();

            String subject = certificate.getSubjectX500Principal().getName();

            LocalDate validFrom = certificate.getNotBefore().toInstant().atZone(ZoneOffset.UTC).toLocalDate();

            LocalDate validUntil = certificate.getNotAfter().toInstant().atZone(ZoneOffset.UTC).toLocalDate();

            long daysUntilExpiration = ChronoUnit.DAYS.between(LocalDate.now(clock), validUntil);

            SslStatus status;
            String recommendation;

            if (daysUntilExpiration < 0) {
                status = SslStatus.CRITICAL;
                recommendation = "Replace the expired SSL certificate immediately.";
            } else if (daysUntilExpiration == 0) {
                status = SslStatus.WARNING;
                recommendation = "The SSL certificate expires today and should be renewed immediately.";
            } else if (daysUntilExpiration <= 30) {
                status = SslStatus.WARNING;
                recommendation = "Renew the SSL certificate before it expires.";
            } else {
                status = SslStatus.GOOD;
                recommendation = null;
            }

            deadline.check();
            return new SslAnalysisResult(
                    issuer,
                    subject,
                    validFrom,
                    validUntil,
                    daysUntilExpiration,
                    status,
                    recommendation
            );

        } catch (AnalysisTimeoutException expired) {
            throw expired;
        } catch (SocketTimeoutException e) {
            deadline.check();

            throw new SslTimeoutException("SSL operation timed out", e);

        } catch (SSLHandshakeException e) {
            deadline.check();

            throw new SslHandshakeAnalysisException("SSL handshake failed", e);

        } catch (Exception e) {
            deadline.check();

            throw new SslAnalysisException("Could not analyze SSL certificate", e);

        }
    }

    private PinnedTlsConnection openPinnedSocket(ValidatedUrl target, String host, int port, AnalysisDeadline deadline) throws IOException {
        IOException lastFailure = new IOException("No approved IP address available");
        for (var address : target.addresses()) {
            deadline.check();
            Socket tcpSocket = tcpSocketFactory.createSocket();
            try (var cancellation = deadline.abortOnTimeout(() -> closeSocket(tcpSocket))) {
                tcpSocket.connect(new InetSocketAddress(address, port), deadline.timeoutMillis(SSL_TIMEOUT_MS));
                deadline.check();
                return new PinnedTlsConnection(tcpSocket, (SSLSocket) socketFactory.createSocket(tcpSocket, host, port, true));
            } catch (IOException | RuntimeException failure) {
                try {
                    tcpSocket.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                deadline.check();
                if (failure instanceof IOException ioFailure) {
                    lastFailure = ioFailure;
                } else {
                    throw failure;
                }
            }
        }
        throw lastFailure;
    }

    private void closeSocket(Socket socket) {
        try {
            socket.close();
        } catch (IOException failure) {
            throw new java.io.UncheckedIOException(failure);
        }
    }

    private record PinnedTlsConnection(Socket tcp, SSLSocket tls) implements java.io.Closeable {
        @Override
        public void close() throws IOException {
            // Close TCP first: TLS shutdown must not wait for a peer's close_notify.
            try (SSLSocket ignored = tls) {
                tcp.close();
            }
        }
    }
}
