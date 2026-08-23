package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.SslAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslHandshakeAnalysisException;
import io.github.raulperezmoreno71.threatintel.exception.SslTimeoutException;
import io.github.raulperezmoreno71.threatintel.model.SslAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SslStatus;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

@Component
public class SslAnalyzer {

    private static final int SSL_TIMEOUT_MS = 5000;

    private final SSLSocketFactory socketFactory;
    private final Clock clock;

    public SslAnalyzer(SSLSocketFactory socketFactory, Clock clock) {
        this.socketFactory = socketFactory;
        this.clock = clock;
    }

    public SslAnalyzer() {
        this(
                (SSLSocketFactory) SSLSocketFactory.getDefault(),
                Clock.systemUTC()
        );
    }

    public SslAnalysisResult analyze (String url, String host) {
        URI uri = URI.create(url);
        int port;

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            return null;
        }

        if (uri.getPort() == -1) {
            port = 443;
        } else {
            port = uri.getPort();
        }

        try (SSLSocket sslSocket = (SSLSocket) socketFactory.createSocket()) {

            sslSocket.connect(new InetSocketAddress(host, port), SSL_TIMEOUT_MS);

            sslSocket.setSoTimeout(SSL_TIMEOUT_MS);

            sslSocket.startHandshake();

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

            return new SslAnalysisResult(
                    issuer,
                    subject,
                    validFrom,
                    validUntil,
                    daysUntilExpiration,
                    status,
                    recommendation
            );

        } catch (SocketTimeoutException e) {

            throw new SslTimeoutException("SSL operation timed out", e);

        } catch (SSLHandshakeException e) {

            throw new SslHandshakeAnalysisException("SSL handshake failed", e);

        } catch (Exception e) {

            throw new SslAnalysisException("Could not analyze SSL certificate", e);

        }
    }
}
