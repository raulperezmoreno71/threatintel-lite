package io.github.raulperezmoreno71.threatintel.exception;

public class AnalysisNotFoundException extends RuntimeException{

    public AnalysisNotFoundException(Long id) {
        super("Analysis not found with id: " + id);
    }
}
