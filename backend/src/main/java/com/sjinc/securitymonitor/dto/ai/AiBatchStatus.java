package com.sjinc.securitymonitor.dto.ai;

import java.time.LocalDateTime;

/** 파이썬 AI 판단 배치가 지금 돌고 있는지 확인하기 위한 상태 응답. */
public record AiBatchStatus(
        boolean running,
        LocalDateTime startedAt,
        LocalDateTime lastFinishedAt,
        Integer lastExitCode // null이면 아직 한 번도 끝난 적이 없다는 뜻(계속 실행 중이거나, 시작한 적 없음)
) {
}
