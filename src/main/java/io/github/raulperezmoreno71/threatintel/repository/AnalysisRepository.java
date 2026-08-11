package io.github.raulperezmoreno71.threatintel.repository;

import io.github.raulperezmoreno71.threatintel.entity.Analysis;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AnalysisRepository extends JpaRepository<Analysis, Long> {
}
