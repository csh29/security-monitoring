package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.FixPlanChange;
import com.sjinc.cvemonitor.domain.VersionJump;
import com.sjinc.cvemonitor.dto.ai.UpgradeImpactTarget;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface FixPlanChangeRepository extends JpaRepository<FixPlanChange, Long> {

    /**
     * 영향 분석 대기 — 점프 폭이 jumps에 들고, 아직 분석 결과가 없거나 일시 오류(FETCH_FAILED)로 끝난 업그레이드.
     * 여러 앱의 fix-plan에 같은 (좌표, from, to)가 있어도 distinct로 한 건만 내려간다.
     */
    @Query("select distinct new com.sjinc.cvemonitor.dto.ai.UpgradeImpactTarget(c.coordinate, c.fromVersion, c.toVersion, c.jump) "
            + "from FixPlanChange c where c.jump in :jumps and not exists ("
            + "  select 1 from UpgradeImpact u where u.coordinate = c.coordinate and u.fromVersion = c.fromVersion "
            + "  and u.toVersion = c.toVersion and u.status <> :retryStatus) "
            + "order by c.coordinate, c.fromVersion, c.toVersion")
    List<UpgradeImpactTarget> findPendingImpactTargets(@Param("jumps") Collection<VersionJump> jumps,
                                                       @Param("retryStatus") String retryStatus);

    boolean existsByCoordinateAndFromVersionAndToVersion(String coordinate, String fromVersion, String toVersion);
}
