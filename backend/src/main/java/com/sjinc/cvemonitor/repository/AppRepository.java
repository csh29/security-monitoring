package com.sjinc.cvemonitor.repository;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.dto.vulnerability.AppVulnerabilityCount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface AppRepository extends JpaRepository<App, Long> {

    List<App> findAllByOrderByIdAsc();

    Optional<App> findByRepoUrlAndBranch(String repoUrl, String branch);

    /**
     * 메인 대시보드용 — 앱마다 OPEN 상태 취약점이 몇 건인지 집계. 취약점이 하나도 없는 앱도
     * 0건으로 보여야 하니 left join으로 앱 전체를 기준으로 삼는다. 건수 내림차순 — 화면에서
     * 상위 N개만 자르면 그대로 "TOP N"이 된다.
     */
    @Query("select new com.sjinc.cvemonitor.dto.vulnerability.AppVulnerabilityCount(a.id, a.systemName, count(v.id)) "
            + "from App a left join Vulnerability v on v.app = a and v.status = 'OPEN' "
            + "group by a.id, a.systemName "
            + "order by count(v.id) desc")
    List<AppVulnerabilityCount> countOpenVulnerabilitiesByApp();
}
