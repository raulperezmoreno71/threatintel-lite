package io.github.raulperezmoreno71.threatintel.support;

import jakarta.servlet.http.Cookie;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.Arrays;

public final class CsrfRequestPostProcessors {

    private static final String CSRF_COOKIE_NAME = "XSRF-TOKEN";
    private static final String CSRF_HEADER_NAME = "X-XSRF-TOKEN";
    private static final String CSRF_TOKEN = "test-csrf-token";

    private CsrfRequestPostProcessors() {
    }

    public static RequestPostProcessor csrfCookieAndHeader() {
        return request -> {
            Cookie[] existingCookies = request.getCookies();
            Cookie[] cookies = existingCookies == null
                    ? new Cookie[1]
                    : Arrays.copyOf(existingCookies, existingCookies.length + 1);

            cookies[cookies.length - 1] = new Cookie(CSRF_COOKIE_NAME, CSRF_TOKEN);
            request.setCookies(cookies);
            request.addHeader(CSRF_HEADER_NAME, CSRF_TOKEN);

            return request;
        };
    }
}
