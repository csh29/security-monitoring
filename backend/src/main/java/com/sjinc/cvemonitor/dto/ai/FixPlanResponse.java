package com.sjinc.cvemonitor.dto.ai;

import com.sjinc.cvemonitor.domain.VersionJump;

import java.time.LocalDateTime;
import java.util.List;

/** 사람이 화면/API로 fix-plan 결과를 확인할 때 쓰는 응답. */
public record FixPlanResponse(
        Long appId,
        String strategy,
        String status,
        String pomXml,
        String unresolvedCves,
        String reasoning,
        String lowSeverityNote,
        LocalDateTime createdAt,
        List<Change> changes
) {
    /**
     * impact는 영향 분석 결과. 패치 점프·UNKNOWN은 분석 대상이 아니라 항상 null이고, 마이너·메이저도 분석 전이면 null이다.
     * codeUsage는 impact의 breaking change를 이 앱의 import·설정 키와 대조한 결과 — impact가 분석 완료이고 breaking change가
     * 있을 때만 값이 있다(impact는 앱 간 공유지만 codeUsage는 앱마다 다르다).
     */
    public record Change(String coordinate, String propertyName, String fromVersion, String toVersion, String via,
                         VersionJump jump, UpgradeImpactView impact, CodeUsageView codeUsage) {
    }
}
