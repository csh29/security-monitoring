package com.sjinc.securitymonitor.dto.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.service.securecode.trace.DollarTraceMerger;
import com.sjinc.securitymonitor.service.securecode.trace.UserScopeFindings;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 코드 점검 결과 화면 한 행(시스템명 포함, 코드는 상세보기에서 따로 받는다). aiVerdict는 판별 결과, 판별 전·입력 변경이면 PENDING, 대상 밖이면 null이다.
 * traceTarget은 판정 대상 식({@code ${ym}} 등)으로, 한 줄에 {@code ${}}가 여럿일 때 행을 구분하려고 매퍼 근거 마지막 줄 "파일:줄 식 (구문)"에서 꺼낸다.
 * 그 형식이 아닌 판정(위험 호출 지점)은 null이다.
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
        String traceSafety,
        String traceLabel,
        String traceTarget,
        List<String> traceEvidence,
        String status,
        String aiVerdict,
        String aiConfidence,
        String aiSummary,
        String aiReasoning,
        String aiAttack,
        String aiFix,
        LocalDateTime aiReviewedAt,
        String statusChangedBy,
        String remark,
        LocalDateTime firstDetectedAt,
        LocalDateTime lastDetectedAt,
        List<Long> sameOriginIds
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

    private static final Set<String> MAPPER_TRACE_RULES =
            Set.of(DollarTraceMerger.RULE_ID, DollarTraceMerger.IBATIS_RULE_ID, UserScopeFindings.RULE_ID);
    /** MyBatis ${…}·#{…}, iBatis $이름$·#이름#(#이름:VARCHAR# 포함) — 근거 마지막 줄 "파일:줄 식 (구문)"의 식. */
    private static final Pattern MAPPER_EXPRESSION = Pattern.compile(
            "[$#]\\{[^}]*}|\\$[A-Za-z_][\\w.\\[\\]]*\\$|#[A-Za-z_][\\w.\\[\\]]*(?:[:,][^#\\s]*)?#");

    static String traceTarget(String ruleId, List<String> evidence) {
        if (!MAPPER_TRACE_RULES.contains(ruleId) || evidence.isEmpty()) return null;
        Matcher m = MAPPER_EXPRESSION.matcher(evidence.get(evidence.size() - 1));
        return m.find() ? m.group() : null;
    }

    /** AI 판별 대기 표시. 판별 결과 값과 겹치지 않는다. */
    public static final String AI_PENDING = "PENDING";
    /** 같은 입력으로 상한만큼 실패해 더 보내지 않는다(입력이 바뀌면 다시 대기). 이유 칸에 마지막 실패 이유를 싣는다. */
    public static final String AI_GIVEN_UP = "GIVEN_UP";

    /**
     * @param aiReviewCurrent 저장된 AI 판별이 지금 입력 기준인가
     * @param aiTarget        AI 판별 대상인가(판별이 없을 때 "대기"로 보일지 정한다)
     * @param aiGivenUp       지금 입력으로 상한만큼 실패해 판별을 포기했는가
     * @param sameOriginIds   같은 출처(SameOrigin)의 다른 탐지 — 화면이 묶어 보여주고, AI는 이들과 한 번에 판별한다
     */
    public static SecureCodeFindingView of(SecureCodeFinding f, String systemName, boolean aiReviewCurrent, boolean aiTarget,
                                           boolean aiGivenUp, List<Long> sameOriginIds) {
        String aiVerdict = aiReviewCurrent ? f.getAiVerdict() : (aiTarget ? (aiGivenUp ? AI_GIVEN_UP : AI_PENDING) : null);
        boolean givenUp = AI_GIVEN_UP.equals(aiVerdict);
        List<String> evidence = f.getTraceEvidence() == null ? List.of() : List.of(f.getTraceEvidence().split("\n"));
        return new SecureCodeFindingView(f.getId(), f.getAppId(), systemName, f.getRuleId(), f.getKisaCategory(),
                f.getKisaName(), f.getCwe(), f.getSeverity(), f.getFilePath(), f.getStartLine(), f.getEndLine(),
                f.getMessage(),
                f.getTraceSafety(), traceLabel(f.getTraceSafety()), traceTarget(f.getRuleId(), evidence), evidence,
                f.getStatus(), aiVerdict,
                aiReviewCurrent ? f.getAiConfidence() : null,
                aiReviewCurrent ? f.getAiSummary() : null,
                aiReviewCurrent ? f.getAiReasoning() : (givenUp ? f.getAiLastError() : null),
                aiReviewCurrent ? f.getAiAttack() : null,
                aiReviewCurrent ? f.getAiFix() : null,
                aiReviewCurrent ? f.getAiReviewedAt() : null,
                f.getStatusChangedBy(),
                f.getRemark(), f.getFirstDetectedAt(), f.getLastDetectedAt(), sameOriginIds);
    }
}
