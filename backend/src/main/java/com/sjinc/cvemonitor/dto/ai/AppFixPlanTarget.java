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
            String aiConfidence,
            // dependency:tree상 이 아티팩트를 끌고 들어온 최상위 직접 의존성("groupId:artifactId").
            // 직접 의존성 자신이면 스스로를 가리킨다. 이게 없으면 AI가 tree 텍스트만 보고 직접/전이 여부를
            // 스스로 추론해야 해서, logstash-logback-encoder처럼 이름이 다른 경우 reasoning에서 누락되기 쉽다.
            String broughtInBy
    ) {
    }
}
