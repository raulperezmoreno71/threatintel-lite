package io.github.raulperezmoreno71.threatintel.service;

import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import io.github.raulperezmoreno71.threatintel.exception.AnalysisNotFoundException;
import io.github.raulperezmoreno71.threatintel.repository.AnalysisRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AnalysisHistoryService {

    private final AnalysisRepository analysisRepository;

    public AnalysisHistoryService(AnalysisRepository analysisRepository) {
        this.analysisRepository = analysisRepository;
    }

    public List<Analysis> getAllAnalyses() {
        return analysisRepository.findAll();
    }

    public Analysis getAnalysisById(Long id) {
        return analysisRepository.findById(id).orElseThrow(() -> new AnalysisNotFoundException(id));
    }
}
