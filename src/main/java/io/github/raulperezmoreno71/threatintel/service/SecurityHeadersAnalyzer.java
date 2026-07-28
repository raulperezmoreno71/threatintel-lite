package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.SecurityHeaderResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import org.springframework.stereotype.Component;

import java.net.http.HttpResponse;
import java.util.Locale;

@Component
public class SecurityHeadersAnalyzer {

    public SecurityHeadersAnalysisResult analyze (HttpResponse<String> response) {

        SecurityHeaderResult strictTransportSecurity = analyzeStrictTransportSecurity(response);
        SecurityHeaderResult contentSecurityPolicy = analyzeContentSecurityPolicy(response);
        SecurityHeaderResult xFrameOptions = analyzeXFrameOptions(response);
        SecurityHeaderResult xContentTypeOptions = analyzeXContentTypeOptions(response);
        SecurityHeaderResult referrerPolicy = analyzeReferrerPolicy(response);
        SecurityHeaderResult permissionsPolicy = analyzePermissionsPolicy(response);

        return new SecurityHeadersAnalysisResult(
                strictTransportSecurity,
                contentSecurityPolicy,
                xFrameOptions,
                xContentTypeOptions,
                referrerPolicy,
                permissionsPolicy
        );
    }

    private SecurityHeaderResult analyzeXContentTypeOptions (HttpResponse<String> response) {
        String value = response.headers().firstValue("X-Content-Type-Options").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add X-Content-Type-Options with the value 'nosniff'."
            );
        }

        if ("nosniff".equalsIgnoreCase(value.trim())) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.GOOD,
                    null
            );
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Set X-Content-Type-Options to 'nosniff'."
        );
    }

    private SecurityHeaderResult analyzeXFrameOptions (HttpResponse<String> response) {
        String value = response.headers().firstValue("X-Frame-Options").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add the X-Frame-Options header with the value 'DENY' or 'SAMEORIGIN' to protect against clickjacking."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        if ("deny".equals(normalizedValue) || "sameorigin".equals(normalizedValue)) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.GOOD,
                    null
            );
        }

        if (normalizedValue.startsWith("allow-from")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "ALLOW-FROM is obsolete. Consider using 'DENY' or 'SAMEORIGIN'."
            );
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Use 'DENY' or 'SAMEORIGIN' as the X-Frame-Options value."
        );
    }

    private SecurityHeaderResult analyzeStrictTransportSecurity (HttpResponse<String> response) {
        String value = response.headers().firstValue("Strict-Transport-Security").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add the Strict-Transport-Security header with a max-age of at least 31536000 seconds."
            );
        }

        String[] directives = value.split(";");

        for (String directive : directives) {

            String normalizeValue = directive.trim().toLowerCase(Locale.ROOT);

            if (normalizeValue.startsWith("max-age=")){

                try {
                    long maxAge = Long.parseLong(normalizeValue.substring(8).trim());

                    if (maxAge < 0) {
                        return new SecurityHeaderResult(
                                true,
                                value,
                                SecurityStatus.WARNING,
                                "Set max-age to a valid non-negative number of seconds."
                        );
                    }

                    if (maxAge == 0) {
                        return new SecurityHeaderResult(
                                true,
                                value,
                                SecurityStatus.WARNING,
                                "HSTS is disabled. Set max-age to at least 31536000 seconds."
                        );
                    }

                    if (maxAge < 31_536_000) {
                        return new SecurityHeaderResult(
                                true,
                                value,
                                SecurityStatus.WARNING,
                                "Increase max-age to at least 31536000 seconds."
                        );
                    }

                    return new SecurityHeaderResult(
                            true,
                            value,
                            SecurityStatus.GOOD,
                            null
                    );
                } catch (NumberFormatException e) {
                    return new SecurityHeaderResult(
                            true,
                            value,
                            SecurityStatus.WARNING,
                            "Set max-age to a valid non-negative number of seconds."
                    );
                }
            }
        }
        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Add a valid max-age directive to the Strict-Transport-Security header."
        );
    }

    private SecurityHeaderResult analyzeReferrerPolicy (HttpResponse<String> response) {
        String value = response.headers().firstValue("Referrer-Policy").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add the Referrer-Policy header to control how much referrer information is shared."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        String[] policies = normalizedValue.split(",");

        String effectivePolicy = null;

        for (int i = policies.length - 1; i >= 0; i--) {
            String policy = policies[i].trim();

            if (isValidReferrerPolicy(policy)) {
                effectivePolicy = policy;
                break;
            }
        }

        if (effectivePolicy == null) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Use a valid Referrer-Policy value."
            );
        }

        switch (effectivePolicy) {
            case "strict-origin-when-cross-origin", "strict-origin", "same-origin", "no-referrer" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.GOOD,
                        null
                );
            }
            case "origin", "origin-when-cross-origin" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.WARNING,
                        "Consider using 'strict-origin-when-cross-origin' for better privacy protection."
                );
            }
            case "unsafe-url" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.WARNING,
                        "Avoid using 'unsafe-url' as it exposes the full referrer URL to other origins."
                );
            }
            case "no-referrer-when-downgrade" -> {
                return new SecurityHeaderResult(
                        true,
                        value,
                        SecurityStatus.WARNING,
                        "Consider using 'strict-origin-when-cross-origin' instead."
                );
            }
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.WARNING,
                "Use a valid Referrer-Policy value."
        );
    }

    private boolean isValidReferrerPolicy (String policy) {
        return switch (policy) {
            case "no-referrer",
                 "no-referrer-when-downgrade",
                 "origin",
                 "origin-when-cross-origin",
                 "same-origin",
                 "strict-origin",
                 "strict-origin-when-cross-origin",
                 "unsafe-url" -> true;

            default -> false;
        };
    }

    private SecurityHeaderResult analyzePermissionsPolicy (HttpResponse<String> response) {
        String value = response.headers().firstValue("Permissions-Policy").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add a Permissions-Policy header to restrict access to unnecessary browser features."
            );
        }

        if (value.isBlank()) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Configure Permissions-Policy with explicit restrictions for unused browser features."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        if (normalizedValue.contains("'none'")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Use the current Permissions-Policy syntax, such as camera=() and microphone=()."
            );
        }

        if (!normalizedValue.contains("=") || !normalizedValue.contains("(") || !normalizedValue.contains(")")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Use valid Permissions-Policy directives in the form feature=(allowlist)."
            );
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.GOOD,
                null
        );
    }

    private SecurityHeaderResult analyzeContentSecurityPolicy (HttpResponse<String> response) {
        String value = response.headers().firstValue("Content-Security-Policy").orElse(null);

        if (value == null) {
            return new SecurityHeaderResult(
                    false,
                    null,
                    SecurityStatus.MISSING,
                    "Add a Content-Security-Policy header to restrict the sources from which content can be loaded and executed."
            );
        }

        if (value.isBlank()) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Configure Content-Security-Policy with explicit resource restrictions."
            );
        }

        String normalizedValue = value.trim().toLowerCase(Locale.ROOT);

        if (normalizedValue.contains("'unsafe-eval'")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Avoid using 'unsafe-eval' because it allows dynamic JavaScript code execution."
            );
        }

        if (normalizedValue.contains("'unsafe-inline'")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Avoid using 'unsafe-inline'. Use nonces or hashes for required inline scripts and styles."
            );
        }

        if (!normalizedValue.contains("default-src") && !normalizedValue.contains("script-src")) {
            return new SecurityHeaderResult(
                    true,
                    value,
                    SecurityStatus.WARNING,
                    "Add a 'default-src' or 'script-src' directive to restrict JavaScript sources."
            );
        }

        String[] directives = normalizedValue.split(";");

        for (String directive : directives) {
            String normalizedDirective = directive.trim();

            if (normalizedDirective.startsWith("default-src ") || normalizedDirective.startsWith("script-src ")) {
                String sources = normalizedDirective.substring(normalizedDirective.indexOf(' ') + 1).trim();

                if ("*".equals(sources) || sources.startsWith("* ")) {
                    return new SecurityHeaderResult(
                            true,
                            value,
                            SecurityStatus.WARNING,
                            "Avoid wildcard sources in 'default-src' and 'script-src'. Restrict resources to trusted origins."
                    );
                }
            }
        }

        return new SecurityHeaderResult(
                true,
                value,
                SecurityStatus.GOOD,
                null
        );
    }
}
