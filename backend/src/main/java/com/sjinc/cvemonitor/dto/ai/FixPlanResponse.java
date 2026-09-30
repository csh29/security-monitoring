package com.sjinc.cvemonitor.dto.ai;

import com.sjinc.cvemonitor.domain.VersionJump;

import java.time.LocalDateTime;
import java.util.List;

/** 사람이 화면/API로 fix-plan 결과를 확인할 때 쓰는 응답. */
public record FixPlanResponse(
        Long appId,
        String strategy,
        String status,
        String pomXml,
        String unresolvedCves,
        String reasoning,
        String lowSeverityNote,
        LocalDateTime createdAt,
        List<Change> changes
) {
    public record Change(String coordinate, String propertyName, String fromVersion, String toVersion, String via,
                         VersionJump jump) {
    }
}
