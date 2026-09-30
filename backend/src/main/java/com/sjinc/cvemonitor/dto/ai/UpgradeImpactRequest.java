package com.sjinc.cvemonitor.dto.ai;

import java.util.List;

/**
 * 영향 분석 배치가 결과를 되돌려줄 때 보내는 요청. status가 ANALYZED가 아니면(NO_SOURCE / FETCH_FAILED)
 * 분석 필드는 비어 있고 note에 사유가 온다.
 */
public record UpgradeImpactRequest(
        String coordinate,
        String fromVersion,
        String toVersion,
        String status,
        String risk,
        String confidence,
        List<BreakingChange> breakingChanges,
        List<String> requiredActions,
        List<String> testFocus,
        List<Source> sources,
        String note
) {
    public record BreakingChange(String summary, String sourceUrl) {
    }

    public record Source(String kind, String url) {
    }
}
