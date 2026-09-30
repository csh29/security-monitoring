package com.sjinc.cvemonitor.dto.ai;

import java.util.List;

/** 파이썬 fix-plan 배치가 취합 판단을 마친 뒤 결과를 되돌려줄 때 보내는 요청 본문. */
public record FixPlanRequest(
        String strategy,
        String pomXml,
        String unresolvedCves,
        String reasoning,
        // pom.xml에서 바꾼 버전 값 목록. 이 필드가 생기기 전의 배치는 보내지 않으므로 null일 수 있다.
        List<Change> changes
) {
    /** via: PARENT / BOM / PROPERTY / DIRECT. propertyName은 PROPERTY일 때만 값이 있다. */
    public record Change(String coordinate, String propertyName, String fromVersion, String toVersion, String via) {
    }
}
