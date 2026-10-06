package com.sjinc.securitymonitor.dto.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.service.securecode.TraceSafety;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 코드 점검 결과 화면 한 행. 엔티티에 없는 시스템명을 붙여 내려준다.
 *
 * <p>aiVerdict는 AI 판별 결과(VULNERABLE/NOT_VULNERABLE/UNCERTAIN), 대상인데 아직 판별 전이거나 재점검으로 입력이 바뀌었으면
 * PENDING, 대상이 아니면 null이다. 옛 입력 기준 판별은 내려주지 않는다(SecureCodeAiReviewService.isReviewCurrent).
 */
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
        String aiVerdict,
        String aiConfidence,
        String aiReasoning,
        LocalDateTime aiReviewedAt,
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

    /** AI 판별 대기 표시. 판별 결과 값과 겹치지 않는다. */
    public static final String AI_PENDING = "PENDING";

    /**
     * @param aiReviewCurrent 저장된 AI 판별이 지금 입력 기준인가
     * @param aiTarget        AI 판별 대상인가(판별이 없을 때 "대기"로 보일지 정한다)
     */
    public static SecureCodeFindingView of(SecureCodeFinding f, String systemName, boolean aiReviewCurrent, boolean aiTarget) {
        String aiVerdict = aiReviewCurrent ? f.getAiVerdict() : (aiTarget ? AI_PENDING : null);
        return new SecureCodeFindingView(f.getId(), f.getAppId(), systemName, f.getRuleId(), f.getKisaCategory(),
                f.getKisaName(), f.getCwe(), f.getSeverity(), f.getFilePath(), f.getStartLine(), f.getEndLine(),
                f.getMessage(), f.getSnippet(), f.getSnippetStartLine(),
                f.getTraceSafety(), traceLabel(f.getTraceSafety()),
                f.getTraceEvidence() == null ? List.of() : List.of(f.getTraceEvidence().split("\n")),
                f.getStatus(), aiVerdict,
                aiReviewCurrent ? f.getAiConfidence() : null,
                aiReviewCurrent ? f.getAiReasoning() : null,
                aiReviewCurrent ? f.getAiReviewedAt() : null,
                f.getStatusChangedBy(),
                f.getRemark(), f.getFirstDetectedAt(), f.getLastDetectedAt());
    }
}
