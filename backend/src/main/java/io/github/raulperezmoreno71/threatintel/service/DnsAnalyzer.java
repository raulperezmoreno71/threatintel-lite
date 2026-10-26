package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.exception.DnsResolutionException;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisTimeoutException;
import io.github.raulperezmoreno71.threatintel.exception.DnsResolverBusyException;
import io.github.raulperezmoreno71.threatintel.model.DnsAnalysisResult;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Component
public class DnsAnalyzer {

    private static final ThreadPoolExecutor workers = new ThreadPoolExecutor(
            4, 4, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(16), task -> {
                Thread thread = new Thread(task, "analysis-dns");
                thread.setDaemon(true);
                return thread;
            });
    private final ExecutorService resolverExecutor;

    DnsAnalyzer(ExecutorService resolverExecutor) {
        this.resolverExecutor = resolverExecutor;
    }

    public DnsAnalyzer() {
        this(workers);
    }

    public InetAddress[] resolve(String domain, AnalysisDeadline deadline) {
        deadline.check();
        Future<InetAddress[]> lookup;
        try {
            lookup = resolverExecutor.submit(() -> resolve(domain));
        } catch (RejectedExecutionException busy) {
            deadline.check();
            throw new DnsResolverBusyException();
        }
        try {
            InetAddress[] addresses = lookup.get(deadline.remainingNanos(), TimeUnit.NANOSECONDS);
            deadline.check();
            return addresses;
        } catch (TimeoutException expired) {
            throw new AnalysisTimeoutException();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            deadline.check();
            throw new DnsResolutionException("DNS resolution interrupted", interrupted);
        } catch (ExecutionException failure) {
            deadline.check();
            if (failure.getCause() instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (failure.getCause() instanceof Error error) {
                throw error;
            }
            throw new DnsResolutionException("Could not resolve domain IP addresses", failure.getCause());
        } finally {
            lookup.cancel(true);
            if (resolverExecutor instanceof ThreadPoolExecutor pool && lookup instanceof Runnable task) {
                pool.remove(task);
            }
        }
    }

    public DnsAnalysisResult analyze (String domain) {
        return analyze(domain, AnalysisDeadline.startDefault());
    }

    public DnsAnalysisResult analyze(String domain, AnalysisDeadline deadline) {
        InetAddress[] addresses = resolve(domain, deadline);
        List<String> ips = new ArrayList<>();

        for (InetAddress address : addresses) {
            ips.add(address.getHostAddress());
        }

        return new DnsAnalysisResult(ips);
    }

    public InetAddress[] resolve(String domain) {
        try {
            return InetAddress.getAllByName(domain);
        } catch (UnknownHostException e) {
            throw new DnsResolutionException("Could not resolve domain IP addresses", e);
        }
    }
}
