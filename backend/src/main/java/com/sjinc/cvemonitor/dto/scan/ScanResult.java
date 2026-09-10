package com.sjinc.cvemonitor.dto.scan;

import java.util.List;

/** 스캔 결과를 화면에 바로 보여주기 위한 응답. */
public record ScanResult(
        String repoUrl,
        String branch,
        String systemName,
        int totalDependenciesScanned,
        List<DependencyFinding> findings
) {
    public record DependencyFinding(
            String groupId,
            String artifactId,
            String version,
            String identifier, // CVE-xxxx 또는 GHSA-xxxx (CVE 별칭 없을 때)
            String summary
    ) {}
}