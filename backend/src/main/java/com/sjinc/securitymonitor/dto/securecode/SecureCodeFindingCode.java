package com.sjinc.securitymonitor.dto.securecode;

import java.util.List;

/**
 * 상세보기에서 여는 탐지 한 건의 코드 — 걸린 줄을 감싼 메서드(조각)와 연계 추적 근거 걸음마다의 주변 코드.
 * 조각이 메서드 단위(최대 80줄)라 목록 API에 넣으면 탐지 수천 건에서 응답이 수 MB가 돼, 상세보기를 열 때 한 건씩 받는다.
 *
 * @param traceCode 근거와 같은 순서. 코드가 없는 걸음은 null. 근거·코드가 없으면 빈 목록
 */
public record SecureCodeFindingCode(
        Long id,
        String filePath,
        Integer startLine,
        Integer endLine,
        String snippet,
        Integer snippetStartLine,
        List<TraceStepCode> traceCode
) {
}
