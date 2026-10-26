package io.github.raulperezmoreno71.threatintel.support;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.Base64;

public final class TlsTestSupport {
    private static final char[] PASSWORD = "test-only-password".toCharArray();

    private TlsTestSupport() {
    }

    public static SSLContext serverContext() throws Exception {
        KeyStore keys = loadTestKeys();
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), null, null);
        return context;
    }

    public static SSLContext trustedClientContext() throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ssrf-test", loadTestKeys().getCertificate("ssrf-test"));
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustManagers.getTrustManagers(), null);
        return context;
    }

    private static KeyStore loadTestKeys() throws Exception {
        try (var resource = TlsTestSupport.class.getResourceAsStream("/tls/ssrf-test.p12.base64")) {
            if (resource == null) {
                throw new IllegalStateException("TLS test fixture is missing");
            }
            byte[] bytes = Base64.getMimeDecoder().decode(resource.readAllBytes());
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(new ByteArrayInputStream(bytes), PASSWORD);
            return keys;
        }
    }
}
