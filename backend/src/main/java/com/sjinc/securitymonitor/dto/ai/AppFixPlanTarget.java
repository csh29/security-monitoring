package com.sjinc.securitymonitor.dto.ai;

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
            String aiConfidence,
            // 이 아티팩트를 끌고 들어온 최상위 직접 의존성("groupId:artifactId", 직접 의존성이면 자기 자신).
            // AI가 tree만 보고 직접/전이 여부를 추론하다 누락하지 않게 미리 내려준다.
            String broughtInBy,
            // 최상위 직접 의존성부터 이 아티팩트까지의 조상 체인("A -> B -> C", 직접 의존성이면 null).
            // AI가 경로를 재구성하다 비슷한 이름의 형제 노드를 혼동하지 않게 자바에서 계산해 그대로 인용하게 한다.
            String dependencyPath
    ) {
    }
}
