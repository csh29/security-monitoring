package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.FixPlan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface FixPlanRepository extends JpaRepository<FixPlan, Long> {

    Optional<FixPlan> findByAppId(Long appId);
}
