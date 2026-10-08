package com.sjinc.securitymonitor.dto.securecode;

import java.util.List;

/** 추적 규칙 초안 반영·무시 요청 — 고른 행의 id들. */
public record TraceRuleProposalRequest(List<Long> ids) {
}
