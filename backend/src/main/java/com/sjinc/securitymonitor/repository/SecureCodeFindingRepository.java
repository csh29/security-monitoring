package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusCount;
import com.sjinc.securitymonitor.dto.vulnerability.AppVulnerabilityCount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecureCodeFindingRepository extends JpaRepository<SecureCodeFinding, Long> {

    /**
     * 심각도 높은 것부터(CRITICAL > HIGH > MEDIUM > LOW, 그 밖의 값·빈 값은 맨 뒤). 자바 쪽 SeverityOrder와 같은 순서다 —
     * 등급을 바꾸면 둘 다 고친다. 심각도가 문자열이라 컬럼 순서로는 정렬할 수 없다.
     */
    String SEVERITY_HIGH_FIRST = "case upper(f.severity) when 'CRITICAL' then 0 when 'HIGH' then 1 "
            + "when 'MEDIUM' then 2 when 'LOW' then 3 else 4 end";

    /** 재점검 비교용 — 처리여부와 무관하게 그 앱의 전부(사람이 오탐 처리한 건도 지문으로 찾아야 한다). */
    List<SecureCodeFinding> findByAppId(Long appId);

    /**
     * AI 판별 대기열(SecureCodeAiReviewService) 후보 — OPEN·지워지지 않은 앱·코드 문맥 있음, 심각도 높은 것부터.
     * appId가 null이면 모든 앱. 판별 대상(등급·추가 규칙·연계 추적 판정) 조건은 설정값이라 서비스에서 거른다.
     */
    @Query("select f from SecureCodeFinding f where f.status = 'OPEN' and f.appId in (select a.id from App a) "
            + "and (:appId is null or f.appId = :appId) and f.aiContext is not null "
            + "order by " + SEVERITY_HIGH_FIRST + ", f.id")
    List<SecureCodeFinding> findAiReviewCandidates(@Param("appId") Long appId);

    /** 폐기한 규칙의 남은 탐지 정리(SecureCodeRuleRetirement). */
    List<SecureCodeFinding> findByRuleIdAndStatus(String ruleId, String status);

    /**
     * 화면 조회. appId·status가 null이면 그 조건 없이. 앱 관리에서 지워진 앱의 행은 뺀다(FK가 없어 남아 있을 수 있다).
     * 심각도 높은 것부터, 같은 등급 안에서는 앱·파일·줄 순.
     */
    @Query("select f from SecureCodeFinding f where f.appId in (select a.id from App a) "
            + "and (:appId is null or f.appId = :appId) and (:status is null or f.status = :status) "
            + "order by " + SEVERITY_HIGH_FIRST + ", f.appId, f.filePath, f.startLine, f.id")
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
