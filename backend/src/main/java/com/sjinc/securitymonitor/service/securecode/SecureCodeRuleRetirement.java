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
 * 일부러 폐기한 규칙의 남은 OPEN 탐지를 기동 때 조치완료로 정리한다. 재점검은 실수로 지운 규칙 때문에 탐지가 한꺼번에 해결되지 않게
 * 빠진 규칙을 건드리지 않으므로, 폐기한 규칙은 여기에 (규칙 id → 비고에 남길 대체 수단)으로 적는다. 이미 정리된 건은 다시 건드리지 않는다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecureCodeRuleRetirement {

    static final Map<String, String> RETIRED_RULES = Map.of(
            // 특정 시스템의 사용자 정보 주입 장치가 없는 메서드를 후보로 내던 규칙. 강제 장치가 아니고 다른 시스템엔 없으며,
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
