package com.sjinc.cvemonitor.dto.scan;

import java.util.List;

/** 스캔 결과를 화면에 바로 보여주기 위한 응답. */
public record ScanResult(
        String repoUrl,
        String branch,
        String systemName,
        int totalDependenciesScanned,
        // findings는 (의존성, 식별자) 조합별 원시 목록이라 같은 CVE가 여러 의존성에 걸리면 중복 집계된다.
        // 실제로 DB에 저장되는(=고유 CVE 기준) 건수는 totalVulnerabilitiesFound를 써야 한다.
        int totalVulnerabilitiesFound,
        // NVD 조회 실패로 저장하지 못한 건수. 0이 아니면 이번 스캔 결과는 불완전하다 —
        // "스캔은 성공했는데 일부가 조용히 빠진" 상태를 화면에서 알 수 있어야 해서 따로 내려준다.
        int failedCveCount,
        List<DependencyFinding> findings
) {
    public record DependencyFinding(
            String groupId,
            String artifactId,
            String version,
            String identifier, // CVE-xxxx 또는 GHSA-xxxx (CVE 별칭 없을 때)
            String summary,
            // OSV가 알려주는 수정 버전 후보(쉼표 구분, 여러 브랜치 패치 시 여러 개). 없으면 null.
            String knownFixedVersions
    ) {}
}