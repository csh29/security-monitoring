package com.sjinc.cvemonitor.dto.ai;

/** 파이썬 fix-plan 배치가 취합 판단을 마친 뒤 결과를 되돌려줄 때 보내는 요청 본문. */
public record FixPlanRequest(
        String strategy,
        String pomXml,
        String unresolvedCves,
        String reasoning
) {
}
