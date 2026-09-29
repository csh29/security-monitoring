package com.sjinc.cvemonitor.dto.ai;

/** 파이썬 배치가 설명 요약을 마친 뒤 되돌려주는 요청 본문. descriptionHash는 {@link CveSummaryTarget}에서 받은 값 그대로. */
public record CveSummaryRequest(
        String cveId,
        String summary,
        String descriptionHash
) {
}
