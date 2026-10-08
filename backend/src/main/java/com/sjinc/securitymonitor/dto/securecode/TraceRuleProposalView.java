package com.sjinc.securitymonitor.dto.securecode;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 코드 점검 화면 "추적 규칙 초안" 목록의 한 행.
 *
 * @param kind      변경 종류 이름(세션 덮어쓰기 추가 등)
 * @param effect    반영하면 판정이 어떻게 달라지는지
 * @param evidence  근거(파일:줄 코드)
 * @param automatic 점검 중 바로 반영하는 종류인가(판정을 엄격하게 하거나 판정에 안 쓰는 변경)
 */
public record TraceRuleProposalView(Long id, Long appId, String systemName, String status, String changeType, String kind,
                                    String summary, String effect, List<String> evidence, boolean automatic,
                                    LocalDateTime createdAt, LocalDateTime lastSeenAt, String decidedBy,
                                    LocalDateTime decidedAt, String decisionNote) {
}
