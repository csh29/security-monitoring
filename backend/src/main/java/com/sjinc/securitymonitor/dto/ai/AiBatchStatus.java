package com.sjinc.securitymonitor.dto.ai;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 파이썬 AI 판단 배치가 지금 돌고 있는지 확인하기 위한 상태 응답.
 *
 * @param running      돌고 있는가 — 이 서버가 띄운 것이든, 서버 재기동 전에 띄웠거나 사람이 직접 띄운 것이든(배치가 남기는 PID 파일로 안다)
 * @param lastExitCode null이면 아직 한 번도 끝난 적이 없다는 뜻(계속 실행 중이거나, 시작한 적 없음)
 * @param appId        지금 판별 중인 앱(시큐어코딩). 모르면(전체 앱·서버가 띄우지 않은 배치) null
 * @param queuedAppIds 지금 배치가 끝나면 이어서 판별할 앱(그사이 점검이 끝난 앱)
 */
public record AiBatchStatus(
        boolean running,
        LocalDateTime startedAt,
        LocalDateTime lastFinishedAt,
        Integer lastExitCode,
        Long appId,
        List<Long> queuedAppIds
) {
}
