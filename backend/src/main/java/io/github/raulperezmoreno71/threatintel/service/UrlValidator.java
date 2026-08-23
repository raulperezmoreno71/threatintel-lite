package io.github.raulperezmoreno71.threatintel.service;

import org.springframework.stereotype.Component;

import java.net.URI;

@Component
public class UrlValidator {

    public void validate (String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("URL cannot be null or blank");
        }

        URI uri;

        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("URL has an invalid format", e);
        }

        if (uri.getScheme() == null || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException("URL protocol must be HTTP or HTTPS");
        }

        if (uri.getHost() == null) {
            throw new IllegalArgumentException("URL must contain a valid host");
        }
    }
}
