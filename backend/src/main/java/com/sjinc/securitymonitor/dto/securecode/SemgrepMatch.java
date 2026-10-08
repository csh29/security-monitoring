package com.sjinc.securitymonitor.dto.securecode;

/**
 * Semgrep JSON 결과 한 건에서 쓰는 값만 뽑은 것(SemgrepReportParser).
 *
 * @param ruleId   규칙 id만(Semgrep이 설정 경로를 점으로 이어 앞에 붙이는 접두어는 뗀다)
 * @param severity 공통코드 SEVERITY 값으로 바꾼 심각도
 * @param filePath 저장소 루트 기준, 구분자 /
 * @param startCol 걸린 범위의 시작 열(UTF-8 바이트 기준, 1부터). 같은 규칙이 겹쳐 걸린 것 가리기(NestedMatchMerger)와
 *                 연계 추적이 그 범위의 식을 찾는 데(SinkTracer) 쓴다. 모르면 0
 * @param endCol   걸린 범위의 끝 열(끝 글자 다음). 모르면 0
 */
public record SemgrepMatch(
        String ruleId,
        String kisaCategory,
        String kisaName,
        String cwe,
        String severity,
        String filePath,
        int startLine,
        int endLine,
        String message,
        int startCol,
        int endCol
) {
    /** 열을 모르는 탐지(연계 추적이 만든 탐지·테스트) — 겹침 판단에서 빠진다. */
    public SemgrepMatch(String ruleId, String kisaCategory, String kisaName, String cwe, String severity,
                        String filePath, int startLine, int endLine, String message) {
        this(ruleId, kisaCategory, kisaName, cwe, severity, filePath, startLine, endLine, message, 0, 0);
    }
}
