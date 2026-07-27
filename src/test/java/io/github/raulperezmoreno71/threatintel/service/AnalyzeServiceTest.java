package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AnalyzeServiceTest {

    private AnalyzeService analyzeService;

    @BeforeEach
    void setUp() {
        analyzeService = new AnalyzeService();
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenUrlIsNull() {
        AnalyzeRequest request = new AnalyzeRequest();
        request.setUrl(null);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzeService.analyze(request)
        );

        assertEquals(
                "URL cannot be null or blank",
                exception.getMessage()
        );
    }

    @Test
    void shouldThrowIllegalArgumentExceptionWhenUrlIsBlank() {
        AnalyzeRequest request = new AnalyzeRequest();
        request.setUrl("   ");

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzeService.analyze(request)
        );

        assertEquals(
                "URL cannot be null or blank",
                exception.getMessage()
        );
    }

    @ParameterizedTest
    @CsvSource({
            "ftp://github.com, URL protocol must be HTTP or HTTPS",
            "https:test, URL must contain a valid host",
            "htt!s://github.com, URL has an invalid format",
            "github.com, URL protocol must be HTTP or HTTPS"
    })
    void shouldThrowIllegalArgumentExceptionForInvalidUrls (String url, String expectedMessage) {
        AnalyzeRequest request = new AnalyzeRequest();
        request.setUrl(url);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzeService.analyze(request)
        );

        assertEquals(
                expectedMessage,
                exception.getMessage()
        );
    }
}
