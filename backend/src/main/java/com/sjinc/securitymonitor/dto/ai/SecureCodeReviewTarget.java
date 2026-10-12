package com.sjinc.securitymonitor.dto.ai;

import com.sjinc.securitymonitor.dto.securecode.AiRelatedCode;

import java.util.List;

/**
 * 파이썬 배치가 진짜 취약한지 판별할 코드 점검 탐지 하나(stage 5). code는 비밀값을 가린 코드 문맥이다(SecretMasker).
 * inputHash는 판별 결과와 함께 그대로 되돌려받는다 — 배치가 도는 사이 재점검으로 코드가 바뀌어도, 저장되는 해시는
 * "실제로 판별한 입력"의 것이라 화면에서 숨겨지고 다음 배치에서 다시 대기가 된다(CveSummaryTarget.descriptionHash와 같은 방식).
 *
 * @param traceLabel    연계 추적 판정(판정 불가·클라이언트 값 등). 없으면 null
 * @param traceEvidence 그 판정의 근거 경로(한 줄에 한 걸음)
 * @param relatedCode   탐지 메서드와 함께 보는 다른 메서드들(연계 추적 경로·탐지 메서드가 부르는 메서드, .java만, 비밀값을 가림). 없으면 빈 목록
 * @param sameOrigin    같은 출처의 다른 판별 대기 지점(SameOrigin) — 한 번에 판별하고 결과를 함께 저장한다. 없으면 빈 목록
 */
public record SecureCodeReviewTarget(
        Long id,
        String ruleId,
        String kisaCategory,
        String kisaName,
        String cwe,
        String severity,
        String message,
        String filePath,
        int startLine,
        int endLine,
        String code,
        int codeStartLine,
        String traceLabel,
        List<String> traceEvidence,
        List<AiRelatedCode> relatedCode,
        String inputHash,
        List<SameOriginMember> sameOrigin
) {
    /** 같은 출처 지점을 붙인 사본. 입력 해시는 이 건 것 그대로다(지점마다 자기 해시로 저장한다). */
    public SecureCodeReviewTarget withSameOrigin(List<SameOriginMember> members) {
        return new SecureCodeReviewTarget(id, ruleId, kisaCategory, kisaName, cwe, severity, message, filePath, startLine, endLine,
                code, codeStartLine, traceLabel, traceEvidence, relatedCode, inputHash, List.copyOf(members));
    }
}
