package io.github.raulperezmoreno71.threatintel.entity;

import jakarta.persistence.*;

@Entity
public class SecurityAssessmentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer score;
    private String grade;
    private Integer goodHeaders;
    private Integer warningHeaders;
    private Integer missingHeaders;

    public SecurityAssessmentEntity() {

    }

    public SecurityAssessmentEntity(
            Integer score,
            String grade,
            Integer goodHeaders,
            Integer warningHeaders,
            Integer missingHeaders
    ) {
        this.score = score;
        this.grade = grade;
        this.goodHeaders = goodHeaders;
        this.warningHeaders = warningHeaders;
        this.missingHeaders = missingHeaders;
    }

    public Long getId() {
        return id;
    }

    public Integer getScore() {
        return score;
    }

    public void setScore(Integer score) {
        this.score = score;
    }

    public String getGrade() {
        return grade;
    }

    public void setGrade(String grade) {
        this.grade = grade;
    }

    public Integer getGoodHeaders() {
        return goodHeaders;
    }

    public void setGoodHeaders(Integer goodHeaders) {
        this.goodHeaders = goodHeaders;
    }

    public Integer getWarningHeaders() {
        return warningHeaders;
    }

    public void setWarningHeaders(Integer warningHeaders) {
        this.warningHeaders = warningHeaders;
    }

    public Integer getMissingHeaders() {
        return missingHeaders;
    }

    public void setMissingHeaders(Integer missingHeaders) {
        this.missingHeaders = missingHeaders;
    }
}
