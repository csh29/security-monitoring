package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewRequest;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewTarget;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecureCodeAiReviewServiceTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 6, 12, 0);

    private SecureCodeFindingRepository findingRepository;
    private AppRepository appRepository;
    private SecureCodeAiReviewService service;

    @BeforeEach
    void setUp() {
        findingRepository = mock(SecureCodeFindingRepository.class);
        appRepository = mock(AppRepository.class);
        service = new SecureCodeAiReviewService(findingRepository, appRepository);
        ReflectionTestUtils.setField(service, "severities", List.of("HIGH", "CRITICAL"));
        when(appRepository.findAll()).thenReturn(List.of(App.builder().id(1L).systemName("CRM").build()));
    }

    private static DetectedFinding detected(String fingerprint, String severity, String traceSafety, String aiContext) {
        return new DetectedFinding(fingerprint, "kisa-os-command-exec", "입력데이터 검증", "명령어 삽입", "CWE-78", severity,
                "src/A.java", 5, 5, "메시지", "snippet", 1, traceSafety, traceSafety == null ? null : "근거1\n근거2",
                aiContext, aiContext == null ? null : 3);
    }

    private static SecureCodeFinding finding(long appId, DetectedFinding d) {
        return SecureCodeFinding.detect(appId, d, NOW);
    }

    @Test
    void 결정론으로_못_정한_높은_등급만_대상이다() {
        assertThat(service.isTarget("HIGH", null)).isTrue();
        assertThat(service.isTarget("CRITICAL", null)).isTrue();
        assertThat(service.isTarget("HIGH", "UNKNOWN")).isTrue();
        // 연계 추적이 정한 건은 보내지 않는다(클라이언트 값 HIGH도, 서버 세팅 LOW도).
        assertThat(service.isTarget("HIGH", "CLIENT")).isFalse();
        assertThat(service.isTarget("LOW", "SERVER_SET")).isFalse();
        assertThat(service.isTarget("MEDIUM", null)).isFalse();
        assertThat(service.isTarget(null, null)).isFalse();
    }

    @Test
    void 대기열은_OPEN_대상_중_지워진_앱과_판별을_마친_건을_뺀다() {
        SecureCodeFinding target = finding(1L, detected("a", "HIGH", null, "ctx-a"));
        SecureCodeFinding traced = finding(1L, detected("b", "HIGH", "CLIENT", "ctx-b"));
        SecureCodeFinding medium = finding(1L, detected("c", "MEDIUM", null, null));
        SecureCodeFinding deletedApp = finding(9L, detected("d", "HIGH", null, "ctx-d"));
        SecureCodeFinding reviewed = finding(1L, detected("e", "HIGH", null, "ctx-e"));
        reviewed.applyAiReview("NOT_VULNERABLE", "high", "이유", SecureCodeAiReviewService.toTarget(reviewed).inputHash(), NOW);
        when(findingRepository.findByStatus("OPEN")).thenReturn(List.of(target, traced, medium, deletedApp, reviewed));

        List<SecureCodeReviewTarget> pending = service.getPendingTargets();

        assertThat(pending).extracting(SecureCodeReviewTarget::code).containsExactly("ctx-a");
        assertThat(pending.get(0).codeStartLine()).isEqualTo(3);
    }

    @Test
    void 재점검으로_코드가_바뀌면_옛_판별은_숨겨지고_다시_대기다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", null, "old code"));
        f.applyAiReview("VULNERABLE", "medium", "이유", SecureCodeAiReviewService.toTarget(f).inputHash(), NOW);
        assertThat(SecureCodeAiReviewService.isReviewCurrent(f)).isTrue();

        f.redetect(detected("a", "HIGH", null, "new code"), NOW);
        when(findingRepository.findByStatus("OPEN")).thenReturn(List.of(f));

        assertThat(SecureCodeAiReviewService.isReviewCurrent(f)).isFalse();
        assertThat(service.getPendingTargets()).hasSize(1);
    }

    @Test
    void 줄_번호만_밀리면_다시_판별하지_않는다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", null, "same code"));
        f.applyAiReview("VULNERABLE", "medium", "이유", SecureCodeAiReviewService.toTarget(f).inputHash(), NOW);

        DetectedFinding shifted = new DetectedFinding("a", "kisa-os-command-exec", "입력데이터 검증", "명령어 삽입", "CWE-78",
                "HIGH", "src/A.java", 15, 15, "메시지", "snippet", 11, null, null, "same code", 13);
        f.redetect(shifted, NOW);

        assertThat(SecureCodeAiReviewService.isReviewCurrent(f)).isTrue();
    }

    @Test
    void 문맥이_없으면_화면용_조각을_보내고_비밀값은_가린다() {
        SecureCodeFinding f = finding(1L, new DetectedFinding("a", "r", "분류", "항목", "CWE-1", "HIGH", "A.java", 2, 2,
                "메시지", "String url = \"jdbc:mysql://h/db?password=hunter2\";", 2, null, null, null, null));

        SecureCodeReviewTarget target = SecureCodeAiReviewService.toTarget(f);

        assertThat(target.codeStartLine()).isEqualTo(2);
        assertThat(target.code()).doesNotContain("hunter2").contains("__MASKED_SECRET_");
    }

    @Test
    void 판별_값을_검증하고_저장한다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", null, "ctx"));
        when(findingRepository.findById(7L)).thenReturn(Optional.of(f));

        service.saveReview(7L, new SecureCodeReviewRequest("NOT_VULNERABLE", "high", "  상수만 들어간다  ", "hash"));

        assertThat(f.getAiVerdict()).isEqualTo("NOT_VULNERABLE");
        assertThat(f.getAiReasoning()).isEqualTo("상수만 들어간다");
        assertThat(f.getAiInputHash()).isEqualTo("hash");
        // 처리여부는 사람이 정한다 — AI가 오탐이라 해도 OPEN 그대로.
        assertThat(f.getStatus()).isEqualTo("OPEN");
    }

    @Test
    void 잘못된_판별_요청은_거절한다() {
        when(findingRepository.findById(7L)).thenReturn(Optional.of(finding(1L, detected("a", "HIGH", null, "ctx"))));

        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("SAFE", "high", "이유", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "certain", "이유", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high", " ", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high",
                "가".repeat(SecureCodeAiReviewService.MAX_REASONING_LENGTH + 1), "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high", "이유", null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(8L, new SecureCodeReviewRequest("VULNERABLE", "high", "이유", "h")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
