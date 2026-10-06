package com.sjinc.securitymonitor.dto.securecode;

/**
 * 이번 점검에서 탐지된 한 건 — Semgrep 결과에 코드 조각과 지문을 붙인 것(SecureCodeSnippetBuilder).
 * 저장 전 값이라 엔티티(SecureCodeFinding)와 따로 둔다.
 *
 * @param traceSafety   MyBatis ${} 연계 추적 판정(DollarVerdict.Safety 이름). 추적 대상이 아니거나 못 맞췄으면 null
 * @param traceEvidence 그 판정의 근거 경로(한 줄에 한 걸음). traceSafety가 null이면 null
 */
public record DetectedFinding(
        String fingerprint,
        String ruleId,
        String kisaCategory,
        String kisaName,
        String cwe,
        String severity,
        String filePath,
        int startLine,
        int endLine,
        String message,
        String snippet,
        int snippetStartLine,
        String traceSafety,
        String traceEvidence
) {
    /** 연계 추적 판정을 붙이고 심각도를 그에 맞게 바꾼 사본. 지문은 그대로라 재점검 비교에 영향이 없다. */
    public DetectedFinding withTrace(String newSeverity, String safety, String evidence) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, newSeverity, filePath,
                startLine, endLine, message, snippet, snippetStartLine, safety, evidence);
    }
}
