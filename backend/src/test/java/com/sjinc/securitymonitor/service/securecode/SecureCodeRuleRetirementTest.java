package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecureCodeRuleRetirementTest {

    private static final String RETIRED = "kisa-authz-missing-user-scope";
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 7, 9, 0);

    private static SecureCodeFinding finding(String fingerprint) {
        return SecureCodeFinding.detect(1L, new DetectedFinding(fingerprint, RETIRED, "보안기능", "부적절한 인가", "CWE-285", "MEDIUM",
                "C.java", 3, 3, "메시지", "code", 3, null, null, null, null), NOW);
    }

    @Test
    void 폐기한_규칙의_미조치_탐지를_조치완료로_정리하고_이유를_남긴다() {
        SecureCodeFinding open = finding("a");
        SecureCodeFinding withRemark = finding("b");
        withRemark.changeRemark("검토 중", "kim");
        SecureCodeFindingRepository repository = mock(SecureCodeFindingRepository.class);
        when(repository.findByRuleIdAndStatus(anyString(), eq(SecureCodeFinding.OPEN))).thenReturn(List.of());
        when(repository.findByRuleIdAndStatus(RETIRED, SecureCodeFinding.OPEN)).thenReturn(List.of(open, withRemark));

        new SecureCodeRuleRetirement(repository).retire();

        assertThat(open.getStatus()).isEqualTo(SecureCodeFinding.RESOLVED);
        assertThat(open.getRemark()).contains("규칙 폐기").contains(UserScopeFindings.RULE_ID);
        assertThat(open.getStatusChangedBy()).isEqualTo("system");
        // 사람이 쓴 비고는 지우지 않는다
        assertThat(withRemark.getRemark()).startsWith("검토 중 / 규칙 폐기");
    }

    @Test
    void 사람이_정한_상태는_건드리지_않는다() {
        SecureCodeFinding accepted = finding("a");
        accepted.changeStatusManually(SecureCodeFinding.ACCEPTED, "kim", NOW);

        assertThat(accepted.retireRule("규칙 폐기", NOW)).isFalse();
        assertThat(accepted.getStatus()).isEqualTo(SecureCodeFinding.ACCEPTED);
    }

    @Test
    void 폐기_목록의_규칙은_규칙_폴더에_없다() throws Exception {
        RuleSetLoader.RuleSet rules = new RuleSetLoader().load(java.nio.file.Path.of("../securecode/rules"), List.of());

        assertThat(rules.ruleIds()).doesNotContainAnyElementsOf(SecureCodeRuleRetirement.RETIRED_RULES.keySet());
        assertThat(rules.ruleIds()).doesNotContain(UserScopeFindings.RULE_ID);
    }
}
