package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import com.sjinc.securitymonitor.service.securecode.trace.UserScopeFindings;

/**
 * 폐기한 코드 점검 규칙의 남은 OPEN 탐지를 기동 때 정리한다.
 *
 * <p>재점검은 이번 규칙셋에 없는 규칙의 탐지를 해결 처리하지 않는다(SecureCodeReconciler — 규칙 파일을 실수로 지웠을 때 탐지가 한꺼번에
 * "해결"로 바뀌지 않게). 그래서 규칙을 일부러 없애면 그 탐지는 OPEN으로 영원히 남는다. 일부러 없앤 규칙만 여기 적어, 다음 기동 때
 * OPEN이고 사람이 정하지 않은 건을 조치완료(RESOLVED)로 바꾸고 비고에 이유를 남긴다. 이미 정리된 건은 다시 건드리지 않아 매 기동 돌아도 된다.
 *
 * <p>규칙을 폐기하면 규칙 파일에서 지우고 여기에 (규칙 id → 이유)를 추가한다. 이유는 비고에 그대로 들어가니 대신 무엇이 그 약점을 보는지 적는다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecureCodeRuleRetirement {

    static final Map<String, String> RETIRED_RULES = Map.of(
            // 2026-10-07: 특정 시스템(CRM)의 @AddUserInfo가 없는 컨트롤러 메서드를 후보로 내던 규칙. 그 장치는 강제가 아니고 다른 시스템엔 없으며,
            // 사용자 범위 조건을 쓰지 않는 메서드까지 걸렸다.
            "kisa-authz-missing-user-scope",
            "규칙 폐기(2026-10-07): 사용자 범위 키의 값 출처 판정(" + UserScopeFindings.RULE_ID + ")으로 대체"
    );

    private final SecureCodeFindingRepository findingRepository;

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void retire() {
        LocalDateTime now = LocalDateTime.now();
        RETIRED_RULES.forEach((ruleId, reason) -> {
            List<SecureCodeFinding> open = findingRepository.findByRuleIdAndStatus(ruleId, SecureCodeFinding.OPEN);
            long retired = open.stream().filter(f -> f.retireRule(reason, now)).count();
            if (retired > 0) {
                log.info("폐기한 코드 점검 규칙 {}의 미조치 탐지 {}건을 조치완료로 정리: {}", ruleId, retired, reason);
            }
        });
    }
}
