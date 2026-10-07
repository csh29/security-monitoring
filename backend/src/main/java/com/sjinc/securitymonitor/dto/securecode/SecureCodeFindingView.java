package com.sjinc.securitymonitor.dto.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.service.securecode.DollarTraceMerger;
import com.sjinc.securitymonitor.service.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.UserScopeFindings;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 코드 점검 결과 화면 한 행. 엔티티에 없는 시스템명을 붙여 내려준다.
 *
 * <p>aiVerdict는 AI 판별 결과(VULNERABLE/NOT_VULNERABLE/UNCERTAIN), 대상인데 아직 판별 전이거나 재점검으로 입력이 바뀌었으면
 * PENDING, 대상이 아니면 null이다. 옛 입력 기준 판별은 내려주지 않는다(SecureCodeAiReviewService.isReviewCurrent).
 *
 * <p>traceTarget은 연계 추적 판정의 대상 식({@code ${ym}}, {@code #{loginCompCd}}). 한 줄에 {@code ${}}가 여럿이면 탐지도 여럿인데 위치·항목이
 * 같아 화면에서 어느 행이 어느 값의 판정인지 구분되지 않았다(CRM crd020의 {@code ums_log_${loginBrndzCd}_${ym}}). 매퍼 판정의 근거는 마지막 줄이
 * 항상 "파일:줄 식 (구문)"이라(MybatisDollarTracer.verdict) 거기서 꺼낸다. 그 형식이 아닌 판정(위험 호출 지점)은 null.
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
        String traceTarget,
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

    private static final Set<String> MAPPER_TRACE_RULES = Set.of(DollarTraceMerger.RULE_ID, UserScopeFindings.RULE_ID);
    private static final Pattern MAPPER_EXPRESSION = Pattern.compile("[$#]\\{[^}]*}");

    static String traceTarget(String ruleId, List<String> evidence) {
        if (!MAPPER_TRACE_RULES.contains(ruleId) || evidence.isEmpty()) return null;
        Matcher m = MAPPER_EXPRESSION.matcher(evidence.get(evidence.size() - 1));
        return m.find() ? m.group() : null;
    }

    /** AI 판별 대기 표시. 판별 결과 값과 겹치지 않는다. */
    public static final String AI_PENDING = "PENDING";

    /**
     * @param aiReviewCurrent 저장된 AI 판별이 지금 입력 기준인가
     * @param aiTarget        AI 판별 대상인가(판별이 없을 때 "대기"로 보일지 정한다)
     */
    public static SecureCodeFindingView of(SecureCodeFinding f, String systemName, boolean aiReviewCurrent, boolean aiTarget) {
        String aiVerdict = aiReviewCurrent ? f.getAiVerdict() : (aiTarget ? AI_PENDING : null);
        List<String> evidence = f.getTraceEvidence() == null ? List.of() : List.of(f.getTraceEvidence().split("\n"));
        return new SecureCodeFindingView(f.getId(), f.getAppId(), systemName, f.getRuleId(), f.getKisaCategory(),
                f.getKisaName(), f.getCwe(), f.getSeverity(), f.getFilePath(), f.getStartLine(), f.getEndLine(),
                f.getMessage(), f.getSnippet(), f.getSnippetStartLine(),
                f.getTraceSafety(), traceLabel(f.getTraceSafety()), traceTarget(f.getRuleId(), evidence), evidence,
                f.getStatus(), aiVerdict,
                aiReviewCurrent ? f.getAiConfidence() : null,
                aiReviewCurrent ? f.getAiReasoning() : null,
                aiReviewCurrent ? f.getAiReviewedAt() : null,
                f.getStatusChangedBy(),
                f.getRemark(), f.getFirstDetectedAt(), f.getLastDetectedAt());
    }
}
