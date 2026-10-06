package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.CveSummary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CveSummaryRepository extends JpaRepository<CveSummary, String> {
}
