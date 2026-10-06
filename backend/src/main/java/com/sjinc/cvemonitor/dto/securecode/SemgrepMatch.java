package com.sjinc.cvemonitor.dto.securecode;

/**
 * Semgrep JSON 결과 한 건에서 쓰는 값만 뽑은 것(SemgrepReportParser).
 *
 * @param ruleId   규칙 id만(Semgrep이 설정 경로를 점으로 이어 앞에 붙이는 접두어는 뗀다)
 * @param severity 공통코드 SEVERITY 값으로 바꾼 심각도
 * @param filePath 저장소 루트 기준, 구분자 /
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
        String message
) {
}
