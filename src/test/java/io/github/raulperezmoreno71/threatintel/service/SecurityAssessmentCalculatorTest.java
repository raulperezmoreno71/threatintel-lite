package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.model.SecurityAssessmentResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeaderResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityHeadersAnalysisResult;
import io.github.raulperezmoreno71.threatintel.model.SecurityStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityAssessmentCalculatorTest {

    private SecurityAssessmentCalculator calculator;

    @BeforeEach
    void setUp() {
        calculator = new SecurityAssessmentCalculator();
    }

    @Test
    void shouldReturnPerfectAssessmentWhenAllHeadersAreGood() {
        SecurityHeaderResult goodHeader = createHeader(SecurityStatus.GOOD);

        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = new SecurityHeadersAnalysisResult(
                goodHeader,
                goodHeader,
                goodHeader,
                goodHeader,
                goodHeader,
                goodHeader
        );

        SecurityAssessmentResult securityAssessmentResult = calculator.calculate(securityHeadersAnalysisResult);

        assertEquals(100, securityAssessmentResult.getScore());
        assertEquals("A", securityAssessmentResult.getGrade());
        assertEquals(6, securityAssessmentResult.getGoodHeaders());
        assertEquals(0, securityAssessmentResult.getWarningHeaders());
        assertEquals(0, securityAssessmentResult.getMissingHeaders());
    }

    @Test
    void shouldReturnFailedAssessmentWhenAllHeadersAreMissing() {
        SecurityHeaderResult missingHeader = createHeader(SecurityStatus.MISSING);

        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = new SecurityHeadersAnalysisResult(
                missingHeader,
                missingHeader,
                missingHeader,
                missingHeader,
                missingHeader,
                missingHeader
        );

        SecurityAssessmentResult securityAssessmentResult = calculator.calculate(securityHeadersAnalysisResult);

        assertEquals(0, securityAssessmentResult.getScore());
        assertEquals("F", securityAssessmentResult.getGrade());
        assertEquals(0, securityAssessmentResult.getGoodHeaders());
        assertEquals(0, securityAssessmentResult.getWarningHeaders());
        assertEquals(6, securityAssessmentResult.getMissingHeaders());
    }

    @Test
    void shouldReturnThirtyPointsWhenContentSecurityPolicyIsGood() {
        SecurityHeaderResult missingHeader = createHeader(SecurityStatus.MISSING);
        SecurityHeaderResult goodHeader = createHeader(SecurityStatus.GOOD);

        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = new SecurityHeadersAnalysisResult(
                missingHeader,
                goodHeader,
                missingHeader,
                missingHeader,
                missingHeader,
                missingHeader
        );

        SecurityAssessmentResult securityAssessmentResult = calculator.calculate(securityHeadersAnalysisResult);

        assertEquals(30, securityAssessmentResult.getScore());
        assertEquals("F", securityAssessmentResult.getGrade());
        assertEquals(1, securityAssessmentResult.getGoodHeaders());
        assertEquals(0, securityAssessmentResult.getWarningHeaders());
        assertEquals(5, securityAssessmentResult.getMissingHeaders());
    }

    @Test
    void shouldReturnTenPointsWhenPermissionsPolicyIsGood() {
        SecurityHeaderResult missingHeader = createHeader(SecurityStatus.MISSING);
        SecurityHeaderResult goodHeader = createHeader(SecurityStatus.GOOD);

        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = new SecurityHeadersAnalysisResult(
                missingHeader,
                missingHeader,
                missingHeader,
                missingHeader,
                missingHeader,
                goodHeader
        );

        SecurityAssessmentResult securityAssessmentResult = calculator.calculate(securityHeadersAnalysisResult);

        assertEquals(10, securityAssessmentResult.getScore());
        assertEquals("F", securityAssessmentResult.getGrade());
        assertEquals(1, securityAssessmentResult.getGoodHeaders());
        assertEquals(0, securityAssessmentResult.getWarningHeaders());
        assertEquals(5, securityAssessmentResult.getMissingHeaders());
    }

    @Test
    void shouldReturnMediumScoreWhenAllHeadersAreWarning() {
        SecurityHeaderResult warningHeader = createHeader(SecurityStatus.WARNING);

        SecurityHeadersAnalysisResult securityHeadersAnalysisResult = new SecurityHeadersAnalysisResult(
                warningHeader,
                warningHeader,
                warningHeader,
                warningHeader,
                warningHeader,
                warningHeader
        );

        SecurityAssessmentResult securityAssessmentResult = calculator.calculate(securityHeadersAnalysisResult);

        assertEquals(51, securityAssessmentResult.getScore());
        assertEquals("F", securityAssessmentResult.getGrade());
        assertEquals(0, securityAssessmentResult.getGoodHeaders());
        assertEquals(6, securityAssessmentResult.getWarningHeaders());
        assertEquals(0, securityAssessmentResult.getMissingHeaders());
    }

    @ParameterizedTest(name = "[{index}] score {6} should produce grade {7}")
    @CsvSource({
            "WARNING, GOOD, GOOD, GOOD, GOOD, GOOD, 90, A",
            "GOOD, GOOD, WARNING, GOOD, WARNING, GOOD, 88, B",
            "GOOD, WARNING, GOOD, GOOD, WARNING, GOOD, 80, B",
            "GOOD, WARNING, WARNING, GOOD, GOOD, GOOD, 78, C",
            "GOOD, MISSING, GOOD, GOOD, GOOD, GOOD, 70, C",
            "WARNING, WARNING, WARNING, GOOD, GOOD, GOOD, 68, D",
            "GOOD, MISSING, GOOD, GOOD, GOOD, MISSING, 60, D",
            "GOOD, MISSING, WARNING, GOOD, WARNING, GOOD, 58, F"
    })
    void shouldCalculateCorrectGradeAtEachBoundary(
            SecurityStatus strictTransportSecurityStatus,
            SecurityStatus contentSecurityPolicyStatus,
            SecurityStatus xFrameOptionsStatus,
            SecurityStatus xContentTypeOptionsStatus,
            SecurityStatus referrerPolicyStatus,
            SecurityStatus permissionsPolicyStatus,
            int expectedScore,
            String expectedGrade
    ) {
        SecurityHeadersAnalysisResult securityHeaders =
                new SecurityHeadersAnalysisResult(
                        createHeader(strictTransportSecurityStatus),
                        createHeader(contentSecurityPolicyStatus),
                        createHeader(xFrameOptionsStatus),
                        createHeader(xContentTypeOptionsStatus),
                        createHeader(referrerPolicyStatus),
                        createHeader(permissionsPolicyStatus)
                );

        SecurityAssessmentResult result =
                calculator.calculate(securityHeaders);

        assertEquals(expectedScore, result.getScore());
        assertEquals(expectedGrade, result.getGrade());
    }

    private SecurityHeaderResult createHeader (SecurityStatus status) {
        return new SecurityHeaderResult(
                true,
                "valid-value",
                status,
                null
        );
    }
}