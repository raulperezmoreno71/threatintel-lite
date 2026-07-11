package io.github.raulperezmoreno71.threatintel.controller;

import io.github.raulperezmoreno71.threatintel.dto.AnalyzeRequest;
import io.github.raulperezmoreno71.threatintel.dto.AnalyzeResponse;
import io.github.raulperezmoreno71.threatintel.service.AnalyzeService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AnalyzeController {
    private final AnalyzeService analyzeService;

    public AnalyzeController (AnalyzeService analyzeService) {
        this.analyzeService = analyzeService;
    }

    @PostMapping("/api/analyze")
    public AnalyzeResponse analyze (@RequestBody AnalyzeRequest request) {
        return analyzeService.analyze(request);
    }
}
