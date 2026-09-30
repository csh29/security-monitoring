package com.sjinc.cvemonitor.dto.ai;

import com.sjinc.cvemonitor.dto.ai.UpgradeImpactRequest.BreakingChange;
import com.sjinc.cvemonitor.dto.ai.UpgradeImpactRequest.Source;

import java.time.LocalDateTime;
import java.util.List;

/** fix-plan 조회 응답의 변경 항목에 붙는 영향 분석 결과. */
public record UpgradeImpactView(
        String status,
        String risk,
        String confidence,
        List<BreakingChange> breakingChanges,
        List<String> requiredActions,
        List<String> testFocus,
        List<Source> sources,
        String note,
        LocalDateTime analyzedAt
) {
}
