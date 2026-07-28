package io.github.raulperezmoreno71.threatintel.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class UrlValidatorTest {

    private UrlValidator urlValidator;

    @BeforeEach
    void setUp() {
        urlValidator = new UrlValidator();
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenUrlIsNull() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate(null)
        );

        assertEquals(
                "URL cannot be null or blank",
                exception.getMessage()
        );
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenUrlIsBlank() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate("   ")
        );

        assertEquals(
                "URL cannot be null or blank",
                exception.getMessage()
        );
    }

    @ParameterizedTest(name = "[{index}] url={0}")
    @CsvSource({
            "ftp://github.com, URL protocol must be HTTP or HTTPS",
            "https:test, URL must contain a valid host",
            "htt!s://github.com, URL has an invalid format",
            "github.com, URL protocol must be HTTP or HTTPS"
    })
    void shouldThrowIllegalArgumentExceptionForInvalidUrls (String url, String expectedMessage) {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> urlValidator.validate(url)
        );

        assertEquals(
                expectedMessage,
                exception.getMessage()
        );
    }

    @ParameterizedTest
    @CsvSource({
            "http://github.com",
            "https://github.com",
            "HTTPS://github.com"
    })
    void shouldAcceptValidHttpAndHttpsUrls (String url) {
        assertDoesNotThrow(
                () -> urlValidator.validate(url)
        );
    }
}
