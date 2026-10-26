package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.DefaultSchemePortResolver;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultRoutePlanner;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.io.ModalCloseable;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

public class PinnedHttpTransport {
    private final SSLContext sslContext;

    public PinnedHttpTransport(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    public PinnedHttpTransport() {
        this(null);
    }

    public HttpResponse<String> get(ValidatedUrl target) throws IOException {
        return get(target, AnalysisDeadline.startDefault());
    }

    public HttpResponse<String> get(ValidatedUrl target, AnalysisDeadline deadline) throws IOException {
        deadline.check();
        String host = target.uri().getHost();
        InetAddress[] approvedAddresses = target.addresses().toArray(InetAddress[]::new);
        DnsResolver resolver = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String requestedHost) throws UnknownHostException {
                checkHost(requestedHost);
                return approvedAddresses.clone();
            }

            @Override
            public String resolveCanonicalHostname(String requestedHost) throws UnknownHostException {
                checkHost(requestedHost);
                return requestedHost;
            }

            private void checkHost(String requestedHost) throws UnknownHostException {
                if (!host.equalsIgnoreCase(requestedHost)) {
                    throw new UnknownHostException("Host does not match the validated destination");
                }
            }
        };

        var tlsStrategy = ClientTlsStrategyBuilder.create()
                .setSslContext(sslContext != null ? sslContext : SSLContexts.createSystemDefault())
                .setHostVerificationPolicy(HostnameVerificationPolicy.BOTH)
                .buildClassic();

        var manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(resolver)
                .setTlsSocketStrategy(tlsStrategy)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofMilliseconds(deadline.timeoutMillis(5000))).build())
                .setDefaultSocketConfig(SocketConfig.custom()
                        .setSoTimeout(Timeout.ofMilliseconds(deadline.timeoutMillis(5000))).build())
                .build();

        try (var client = HttpClients.custom()
                .setConnectionManager(manager)
                .setRoutePlanner(new DefaultRoutePlanner(DefaultSchemePortResolver.INSTANCE))
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .disableCookieManagement()
                .disableContentCompression()
                .build()) {
            HttpGet request = new HttpGet(target.uri());
            try (var cancellation = deadline.abortOnTimeout(request::cancel)) {
                var response = client.executeOpen(null, request, null);
                try {
                    Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                    for (var header : response.getHeaders()) {
                        headers.computeIfAbsent(header.getName(), key -> new ArrayList<>()).add(header.getValue());
                    }
                    deadline.check();
                    return new ResponseSnapshot(response.getCode(), HttpHeaders.of(headers, (name, value) -> true), "", target.uri());
                } finally {
                    // Graceful response handling drains the body; discard the connection instead.
                    if (response instanceof ModalCloseable closeable) {
                        closeable.close(CloseMode.IMMEDIATE);
                    } else {
                        client.close(CloseMode.IMMEDIATE);
                        response.close();
                    }
                }
            }
        } catch (IOException | RuntimeException failure) {
            deadline.check();
            throw failure;
        }
    }

    private record ResponseSnapshot(int statusCode, HttpHeaders headers, String body, URI uri) implements HttpResponse<String> {
        @Override
        public HttpRequest request() {
            return HttpRequest.newBuilder(uri).GET().build();
        }

        @Override
        public Optional<HttpResponse<String>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }
}
