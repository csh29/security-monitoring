package com.sjinc.securitymonitor.dto.securecode;

/**
 * 이번 점검에서 탐지된 한 건 — Semgrep 결과에 코드 조각과 지문을 붙인 것(SecureCodeSnippetBuilder).
 * 저장 전 값이라 엔티티(SecureCodeFinding)와 따로 둔다.
 *
 * @param traceSafety        MyBatis ${} 연계 추적 판정(DollarVerdict.Safety 이름). 추적 대상이 아니거나 못 맞췄으면 null
 * @param traceEvidence      그 판정의 근거 경로(한 줄에 한 걸음). traceSafety가 null이면 null
 * @param aiContext          AI 판별에 보낼 코드 문맥(걸린 줄을 감싼 메서드, 길면 걸린 줄 주변). AI 판별 대상이 아니면 null
 * @param aiContextStartLine aiContext 첫 줄의 줄 번호
 * @param traceCode          연계 추적 근거 걸음마다의 주변 코드(TraceStepCode 목록 JSON, 근거와 같은 순서). 근거가 없거나 코드를 못 붙였으면 null
 * @param aiRelated          AI 판별에 탐지 메서드와 함께 보낼 다른 메서드들(AiRelatedCode 목록 JSON — 연계 추적 경로·탐지 메서드가 부르는 메서드).
 *                           AI 판별 대상이 아니거나 없으면 null
 * @param startCol           Semgrep이 걸린 범위의 시작 열(UTF-8 바이트 기준, 1부터) — 연계 추적이 그 범위의 식을 찾는다(SinkTracer). 모르면 0
 * @param endCol             걸린 범위의 끝 열(끝 글자 다음). 모르면 0
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
        String traceEvidence,
        String aiContext,
        Integer aiContextStartLine,
        String traceCode,
        String aiRelated,
        int startCol,
        int endCol
) {
    /** 열 없이 만든다(연계 추적이 만든 탐지·테스트). */
    public DetectedFinding(String fingerprint, String ruleId, String kisaCategory, String kisaName, String cwe, String severity,
                           String filePath, int startLine, int endLine, String message, String snippet, int snippetStartLine,
                           String traceSafety, String traceEvidence, String aiContext, Integer aiContextStartLine, String traceCode,
                           String aiRelated) {
        this(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath, startLine, endLine, message, snippet,
                snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, traceCode, aiRelated, 0, 0);
    }

    /** AI 관련 코드 없이 만든다. */
    public DetectedFinding(String fingerprint, String ruleId, String kisaCategory, String kisaName, String cwe, String severity,
                           String filePath, int startLine, int endLine, String message, String snippet, int snippetStartLine,
                           String traceSafety, String traceEvidence, String aiContext, Integer aiContextStartLine, String traceCode) {
        this(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath, startLine, endLine, message, snippet,
                snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, traceCode, null);
    }

    /** 연계 추적 코드 없이 만든다(점검 초기 단계·테스트). */
    public DetectedFinding(String fingerprint, String ruleId, String kisaCategory, String kisaName, String cwe, String severity,
                           String filePath, int startLine, int endLine, String message, String snippet, int snippetStartLine,
                           String traceSafety, String traceEvidence, String aiContext, Integer aiContextStartLine) {
        this(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath, startLine, endLine, message, snippet,
                snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, null);
    }

    /** 연계 추적 판정을 붙이고 심각도를 그에 맞게 바꾼 사본. 지문은 그대로라 재점검 비교에 영향이 없다. */
    public DetectedFinding withTrace(String newSeverity, String safety, String evidence) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, newSeverity, filePath,
                startLine, endLine, message, snippet, snippetStartLine, safety, evidence, aiContext, aiContextStartLine, traceCode, aiRelated, startCol, endCol);
    }

    /** AI 판별용 코드 문맥을 붙인 사본. */
    public DetectedFinding withAiContext(String context, Integer contextStartLine) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath,
                startLine, endLine, message, snippet, snippetStartLine, traceSafety, traceEvidence, context, contextStartLine, traceCode, aiRelated, startCol, endCol);
    }

    /** 같은 줄·같은 CWE의 다른 규칙 탐지를 합친 사본(DuplicateCweMerger) — 등급과 설명만 바뀐다. 지문은 그대로. */
    public DetectedFinding withMerged(String newSeverity, String newMessage) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, newSeverity, filePath,
                startLine, endLine, newMessage, snippet, snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, traceCode, aiRelated, startCol, endCol);
    }

    /** 연계 추적 근거 걸음마다의 주변 코드(JSON)를 붙인 사본. */
    public DetectedFinding withTraceCode(String code) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath,
                startLine, endLine, message, snippet, snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, code, aiRelated, startCol, endCol);
    }

    /** Semgrep이 걸린 범위의 열을 붙인 사본(SecureCodeSnippetBuilder.build). */
    public DetectedFinding withColumns(int newStartCol, int newEndCol) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath,
                startLine, endLine, message, snippet, snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, traceCode, aiRelated,
                newStartCol, newEndCol);
    }

    /** AI 판별에 함께 보낼 관련 코드(JSON)를 붙인 사본. */
    public DetectedFinding withAiRelated(String related) {
        return new DetectedFinding(fingerprint, ruleId, kisaCategory, kisaName, cwe, severity, filePath,
                startLine, endLine, message, snippet, snippetStartLine, traceSafety, traceEvidence, aiContext, aiContextStartLine, traceCode, related, startCol, endCol);
    }
}
