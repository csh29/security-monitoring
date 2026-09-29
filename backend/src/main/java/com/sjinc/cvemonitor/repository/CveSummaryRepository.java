package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.CveSummary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CveSummaryRepository extends JpaRepository<CveSummary, String> {
}
