package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.UpgradeImpact;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UpgradeImpactRepository extends JpaRepository<UpgradeImpact, Long> {

    Optional<UpgradeImpact> findByCoordinateAndFromVersionAndToVersion(String coordinate, String fromVersion, String toVersion);
}
