package com.sjinc.cvemonitor.dto.ai;

/** 파이썬 AI 배치가 CVE 판단을 마친 뒤 결과를 되돌려줄 때 보내는 요청 본문. */
public record AiAssessmentRequest(
        boolean vulnerable,
        String fixedVersion,
        String reasoning,
        String confidence
) {
}
