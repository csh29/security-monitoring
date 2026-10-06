package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecureCodeReconcilerTest {

    private static final Long APP_ID = 1L;
    private static final LocalDateTime T0 = LocalDateTime.of(2026, 10, 1, 9, 0);
    private static final LocalDateTime T1 = T0.plusDays(1);
    private static final Set<String> RULES = Set.of("rule-a", "rule-b");

    private static DetectedFinding detected(String fingerprint, String ruleId, String path, int line) {
        return new DetectedFinding(fingerprint, ruleId, "분류", "항목", "CWE-1", "HIGH", path, line, line, "메시지", "code", line, null, null);
    }

    private static SecureCodeFinding existing(String fingerprint, String ruleId, String path) {
        return SecureCodeFinding.detect(APP_ID, detected(fingerprint, ruleId, path, 1), T0);
    }

    private static SecureCodeReconciler.Result reconcile(List<SecureCodeFinding> existing, List<DetectedFinding> detected,
                                                         Set<String> failedFiles) {
        return SecureCodeReconciler.reconcile(APP_ID, existing, detected, failedFiles, RULES, T1);
    }

    @Test
    void 처음_보는_지문은_신규_OPEN() {
        SecureCodeReconciler.Result result = reconcile(List.of(), List.of(detected("f1", "rule-a", "A.java", 3)), Set.of());

        assertThat(result.newCount()).isEqualTo(1);
        assertThat(result.toSave()).singleElement().satisfies(f -> {
            assertThat(f.getStatus()).isEqualTo(SecureCodeFinding.OPEN);
            assertThat(f.getFirstDetectedAt()).isEqualTo(T1);
        });
    }

    @Test
    void 이미_있는_지문은_위치만_갱신하고_신규로_세지_않는다() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(detected("f1", "rule-a", "A.java", 9)), Set.of());

        assertThat(result.newCount()).isZero();
        assertThat(f1.getStartLine()).isEqualTo(9);
        assertThat(f1.getFirstDetectedAt()).isEqualTo(T0);
        assertThat(f1.getLastDetectedAt()).isEqualTo(T1);
    }

    @Test
    void 안_걸린_OPEN은_해결() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(), Set.of());

        assertThat(result.resolvedCount()).isEqualTo(1);
        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.RESOLVED);
        assertThat(f1.getResolvedAt()).isEqualTo(T1);
    }

    @Test
    void 분석에_실패한_파일의_탐지는_해결하지_않는다() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "Broken.java");

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(), Set.of("Broken.java"));

        assertThat(result.resolvedCount()).isZero();
        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.OPEN);
    }

    @Test
    void 규칙셋에서_빠진_규칙의_탐지는_해결하지_않는다() {
        SecureCodeFinding f1 = existing("f1", "rule-removed", "A.java");

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(), Set.of());

        assertThat(result.resolvedCount()).isZero();
        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.OPEN);
    }

    @Test
    void 스캔이_해결한_건이_다시_걸리면_OPEN으로_되돌리고_신규로_센다() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");
        f1.resolveByScan(T0);

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(detected("f1", "rule-a", "A.java", 1)), Set.of());

        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.OPEN);
        assertThat(f1.getResolvedAt()).isNull();
        assertThat(result.newCount()).isEqualTo(1);
    }

    @Test
    void 사람이_오탐으로_처리한_건은_다시_걸려도_유지() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");
        f1.changeStatusManually(SecureCodeFinding.FALSE_POSITIVE, "admin", T0);

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(detected("f1", "rule-a", "A.java", 1)), Set.of());

        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.FALSE_POSITIVE);
        assertThat(result.newCount()).isZero();
    }

    @Test
    void 사람이_정한_상태는_안_걸려도_해결로_바꾸지_않는다() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");
        f1.changeStatusManually(SecureCodeFinding.ACCEPTED, "admin", T0);

        SecureCodeReconciler.Result result = reconcile(List.of(f1), List.of(), Set.of());

        assertThat(result.resolvedCount()).isZero();
        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.ACCEPTED);
    }

    @Test
    void 사람이_조치완료로_한_건은_다시_걸려도_유지하고_OPEN으로_되돌리면_스캔을_따른다() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");
        f1.changeStatusManually(SecureCodeFinding.RESOLVED, "admin", T0);
        reconcile(List.of(f1), List.of(detected("f1", "rule-a", "A.java", 1)), Set.of());
        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.RESOLVED);

        f1.changeStatusManually(SecureCodeFinding.OPEN, "admin", T0);
        assertThat(f1.getStatusManual()).isNull();
        reconcile(List.of(f1), List.of(), Set.of());
        assertThat(f1.getStatus()).isEqualTo(SecureCodeFinding.RESOLVED);
    }

    @Test
    void 한_결과에_같은_지문이_두번_와도_한_건만_만든다() {
        SecureCodeReconciler.Result result = reconcile(List.of(),
                List.of(detected("f1", "rule-a", "A.java", 1), detected("f1", "rule-a", "A.java", 2)), Set.of());

        assertThat(result.toSave()).hasSize(1);
        assertThat(result.newCount()).isEqualTo(1);
    }

    @Test
    void 허용되지_않은_처리여부는_거절() {
        SecureCodeFinding f1 = existing("f1", "rule-a", "A.java");

        assertThatThrownBy(() -> f1.changeStatusManually("DONE", "admin", T0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
