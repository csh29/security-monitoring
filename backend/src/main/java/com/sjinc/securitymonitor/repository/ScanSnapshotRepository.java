package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.ScanSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface ScanSnapshotRepository extends JpaRepository<ScanSnapshot, Long> {

    Optional<ScanSnapshot> findByAppId(Long appId);

    /** 스냅샷은 있는데 아직 fix-plan을 안 만들었거나, 그 뒤로 재스캔돼서 스냅샷이 갱신된 앱들. */
    @Query("select s from ScanSnapshot s where s.pomXml is not null "
            + "and (s.fixPlanGeneratedAt is null or s.scannedAt > s.fixPlanGeneratedAt)")
    List<ScanSnapshot> findPendingFixPlanTargets();
}
