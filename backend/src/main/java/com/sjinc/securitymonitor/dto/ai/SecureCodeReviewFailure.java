package com.sjinc.securitymonitor.dto.ai;

import java.util.List;

/**
 * 배치가 판별에 실패했다고 알리는 요청(파이썬 report_secure_code_failure). 일시 오류(요청 한도·연결·서버 오류)는 보내지 않는다 —
 * 같은 입력으로 다시 해도 또 실패할 것(응답 잘림·형식 오류·저장 거절)만 센다.
 *
 * @param inputHash  판별하려던 입력의 해시(pending에서 받은 값 그대로)
 * @param reason     실패 이유(500자로 자른다)
 * @param sameOrigin 대표와 함께 판별하려던 같은 출처 지점 — 함께 센다(대표만 세면 대표가 빠진 뒤 다음 지점이 대표가 되어 또 실패·과금된다)
 */
public record SecureCodeReviewFailure(String inputHash, String reason, List<SameOriginRef> sameOrigin) {

    public SecureCodeReviewFailure(String inputHash, String reason) {
        this(inputHash, reason, List.of());
    }
}
