package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusCount;
import com.sjinc.securitymonitor.dto.vulnerability.AppVulnerabilityCount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecureCodeFindingRepository extends JpaRepository<SecureCodeFinding, Long> {

    /** 재점검 비교용 — 처리여부와 무관하게 그 앱의 전부(사람이 오탐 처리한 건도 지문으로 찾아야 한다). */
    List<SecureCodeFinding> findByAppId(Long appId);

    /** 화면 조회. appId·status가 null이면 그 조건 없이. */
    @Query("select f from SecureCodeFinding f where (:appId is null or f.appId = :appId) "
            + "and (:status is null or f.status = :status) "
            + "order by f.appId, f.filePath, f.startLine, f.id")
    List<SecureCodeFinding> search(@Param("appId") Long appId, @Param("status") String status);

    /** 홈 대시보드 KPI. 앱 관리에서 지워진 앱의 행은 뺀다(FK가 없어 남아 있을 수 있다 — 화면 조회와 같은 기준). */
    @Query("select new com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusCount(f.status, f.severity, count(f)) "
            + "from SecureCodeFinding f where f.appId in (select a.id from App a) "
            + "group by f.status, f.severity")
    List<SecureCodeStatusCount> countByStatusAndSeverity();

    /**
     * 홈 대시보드 앱별 막대 — 앱마다 미조치 건수. 탐지가 없는 앱도 0건으로 보이도록 앱 기준 left join
     * (AppRepository.countOpenVulnerabilitiesByApp과 같은 모양). 건수 내림차순.
     */
    @Query("select new com.sjinc.securitymonitor.dto.vulnerability.AppVulnerabilityCount(a.systemName, count(f.id)) "
            + "from App a left join SecureCodeFinding f on f.appId = a.id and f.status = 'OPEN' "
            + "group by a.id, a.systemName "
            + "order by count(f.id) desc")
    List<AppVulnerabilityCount> countOpenByApp();
}
