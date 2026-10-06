package com.sjinc.securitymonitor.dto.ai;

/**
 * 파이썬 배치가 요약할 CVE 하나. descriptionHash는 요약 결과와 함께 그대로 되돌려받는다 — 배치가 도는 사이
 * 재스캔으로 설명이 바뀌어도, 저장되는 해시는 "실제로 요약한 설명"의 것이라 다음 배치에서 다시 대기가 된다.
 */
public record CveSummaryTarget(
        String cveId,
        String description,
        String descriptionHash
) {
}
