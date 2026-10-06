package com.sjinc.securitymonitor.dto.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.service.securecode.TraceSafety;

import java.time.LocalDateTime;
import java.util.List;

/** 코드 점검 결과 화면 한 행. 엔티티에 없는 시스템명을 붙여 내려준다. */
public record SecureCodeFindingView(
        Long id,
        Long appId,
        String systemName,
        String ruleId,
        String kisaCategory,
        String kisaName,
        String cwe,
        String severity,
        String filePath,
        Integer startLine,
        Integer endLine,
        String message,
        String snippet,
        Integer snippetStartLine,
        String traceSafety,
        String traceLabel,
        List<String> traceEvidence,
        String status,
        String statusChangedBy,
        String remark,
        LocalDateTime firstDetectedAt,
        LocalDateTime lastDetectedAt
) {
    /** 판정 이름 → 화면 표시. 예전 값·모르는 값이면 이름 그대로(화면이 비지 않게). */
    private static String traceLabel(String safety) {
        if (safety == null) return null;
        try {
            return TraceSafety.valueOf(safety).label();
        } catch (IllegalArgumentException e) {
            return safety;
        }
    }

    public static SecureCodeFindingView of(SecureCodeFinding f, String systemName) {
        return new SecureCodeFindingView(f.getId(), f.getAppId(), systemName, f.getRuleId(), f.getKisaCategory(),
                f.getKisaName(), f.getCwe(), f.getSeverity(), f.getFilePath(), f.getStartLine(), f.getEndLine(),
                f.getMessage(), f.getSnippet(), f.getSnippetStartLine(),
                f.getTraceSafety(), traceLabel(f.getTraceSafety()),
                f.getTraceEvidence() == null ? List.of() : List.of(f.getTraceEvidence().split("\n")),
                f.getStatus(), f.getStatusChangedBy(),
                f.getRemark(), f.getFirstDetectedAt(), f.getLastDetectedAt());
    }
}
