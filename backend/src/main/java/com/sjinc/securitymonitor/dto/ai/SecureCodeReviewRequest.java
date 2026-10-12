package com.sjinc.securitymonitor.dto.ai;

import java.util.List;

/**
 * 배치가 보내는 코드 점검 탐지 판별(파이썬 SecureCodeReview). 사람이 읽기 쉽게 항목을 나눠 받는다.
 *
 * @param summary    결론 한 문장
 * @param reasoning  근거 — 줄 번호를 단 글머리 몇 개
 * @param attack     예상 공격(어떤 요청으로 무엇이 되는가). 취약하지 않으면 빈 값
 * @param fix        조치 방법(어느 줄을 어떻게). 취약하지 않으면 빈 값
 * @param sameOrigin 이 판별을 함께 저장할 같은 출처 지점(pending의 sameOrigin을 그대로). 없으면 빈 목록
 */
public record SecureCodeReviewRequest(
        String verdict,
        String confidence,
        String summary,
        String reasoning,
        String attack,
        String fix,
        String inputHash,
        List<SameOriginRef> sameOrigin
) {
    /** 같은 출처 지점 없이(테스트). */
    public SecureCodeReviewRequest(String verdict, String confidence, String summary, String reasoning, String attack, String fix,
                                   String inputHash) {
        this(verdict, confidence, summary, reasoning, attack, fix, inputHash, List.of());
    }
}
