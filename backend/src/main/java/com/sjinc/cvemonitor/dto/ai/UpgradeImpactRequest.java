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
    /**
     * symbols: 이 변경이 가리키는 클래스·패키지·설정 키 이름(원문 그대로). 서버가 앱의 import·설정 키 목록과 대조해 "우리 코드에서
     * 쓰는가"를 판단한다(CodeUsageMatcher). 이름으로 가리킬 수 없는 변경(기본 동작 변경 등)이면 빈 목록이고, 이 필드가 생기기 전
     * 저장된 결과는 null이다.
     */
    public record BreakingChange(String summary, String sourceUrl, List<String> symbols) {
    }

    public record Source(String kind, String url) {
    }
}
