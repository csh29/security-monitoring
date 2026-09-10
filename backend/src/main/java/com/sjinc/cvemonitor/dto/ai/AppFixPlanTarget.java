package com.sjinc.cvemonitor.dto.ai;

import java.util.List;

/** fix-plan 배치가 앱 하나를 처리하는 데 필요한 입력을 한 번에 묶어서 내려주는 응답. */
public record AppFixPlanTarget(
        Long appId,
        String systemName,
        String pomXml,
        String dependencyTree,
        List<CveFinding> cveFindings
) {
    /** stage-1(개별 CVE 판단)에서 이미 "취약함"으로 확정된 CVE 하나. */
    public record CveFinding(
            String cveId,
            String groupId,
            String artifactId,
            String installedVersion,
            String aiFixedVersion,
            String aiConfidence
    ) {
    }
}
