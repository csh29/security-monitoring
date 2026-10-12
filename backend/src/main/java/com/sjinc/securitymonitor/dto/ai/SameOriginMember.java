package com.sjinc.securitymonitor.dto.ai;

/**
 * AI 판별 대표 건과 같은 출처(SameOrigin)인 다른 지점 — 대표와 한 번에 판별하고 결과를 함께 저장한다.
 *
 * @param inputHash 이 지점의 입력 해시(판별을 이 지점에 저장할 때 쓴다 — 지점마다 코드가 달라 해시도 다르다)
 * @param sink      연계 추적 근거의 마지막 걸음(값이 닿는 위험 호출)
 * @param code      위험 호출 주변 코드(비밀값을 가림). 지점이 많으면 앞의 몇 개만 싣고 나머지는 null(위치만)
 */
public record SameOriginMember(
        Long id,
        String inputHash,
        String filePath,
        int startLine,
        String ruleId,
        String sink,
        String code,
        int codeStartLine
) {
}
