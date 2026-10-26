package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import io.github.raulperezmoreno71.threatintel.model.ValidatedUrl;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class HttpDeadlineTest {

    @Test
    void shouldAbortSlowHeadersEvenWhileBytesKeepArriving() throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        CountDownLatch release = new CountDownLatch(1);
        try (ServerSocket server = new ServerSocket(0, 1, loopback);
             var executor = Executors.newFixedThreadPool(2)) {
            server.setSoTimeout(4000);
            var peer = executor.submit(() -> {
                try (var socket = server.accept()) {
                    socket.setSoTimeout(4000);
                    var input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                    String line;
                    while ((line = input.readLine()) != null && !line.isEmpty()) {
                        // Wait for the complete GET request.
                    }
                    var output = socket.getOutputStream();
                    output.write("HTTP/1.1 200 OK\r\nX-Slow: ".getBytes(StandardCharsets.US_ASCII));
                    output.flush();
                    try {
                        while (!release.await(25, TimeUnit.MILLISECONDS)) {
                            output.write('x');
                            output.flush();
                        }
                        return false;
                    } catch (java.io.IOException disconnected) {
                        return true;
                    }
                }
            });
            try {
                URI uri = URI.create("http://rebind.invalid:" + server.getLocalPort());
                var target = new ValidatedUrl(uri, List.of(loopback));
                var request = executor.submit(() -> new PinnedHttpTransport().get(target,
                        AnalysisDeadline.start(Duration.ofSeconds(1))));

                ExecutionException failure = assertThrows(ExecutionException.class, () -> request.get(3, TimeUnit.SECONDS));

                assertInstanceOf(AnalysisTimeoutException.class, failure.getCause());
                assertTrue(peer.get(2, TimeUnit.SECONDS), "Deadline must disconnect the HTTP socket");
            } finally {
                release.countDown();
            }
        }
    }
}
