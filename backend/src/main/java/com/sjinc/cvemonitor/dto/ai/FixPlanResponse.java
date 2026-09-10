package com.sjinc.cvemonitor.dto.ai;

import java.time.LocalDateTime;

/** 사람이 화면/API로 fix-plan 결과를 확인할 때 쓰는 응답. */
public record FixPlanResponse(
        Long appId,
        String strategy,
        String status,
        String pomXml,
        String unresolvedCves,
        String reasoning,
        String lowSeverityNote,
        LocalDateTime createdAt
) {
}
