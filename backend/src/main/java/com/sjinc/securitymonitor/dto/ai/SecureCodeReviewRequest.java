package com.sjinc.securitymonitor.dto.ai;

/** 파이썬 배치가 코드 점검 탐지 판별을 마친 뒤 되돌려주는 요청 본문. inputHash는 {@link SecureCodeReviewTarget}에서 받은 값 그대로. */
public record SecureCodeReviewRequest(
        String verdict,
        String confidence,
        String reasoning,
        String inputHash
) {
}
