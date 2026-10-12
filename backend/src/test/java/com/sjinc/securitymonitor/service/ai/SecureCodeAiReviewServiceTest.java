package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.ai.SameOriginMember;
import com.sjinc.securitymonitor.dto.ai.SameOriginRef;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewFailure;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewRequest;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewTarget;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecureCodeAiReviewServiceTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 6, 12, 0);

    private SecureCodeFindingRepository findingRepository;
    private SecureCodeAiReviewService service;

    @BeforeEach
    void setUp() {
        findingRepository = mock(SecureCodeFindingRepository.class);
        service = new SecureCodeAiReviewService(findingRepository);
        ReflectionTestUtils.setField(service, "severities", List.of("HIGH", "MEDIUM"));
        ReflectionTestUtils.setField(service, "extraRules", List.of("kisa-insecure-random", "kisa-xxe-parser"));
        ReflectionTestUtils.setField(service, "maxFailures", 3);
        ReflectionTestUtils.setField(service, "maxPerRun", 200);
    }

    private static final String RULE = "kisa-os-command-exec";

    private static DetectedFinding detected(String fingerprint, String severity, String traceSafety, String aiContext) {
        return new DetectedFinding(fingerprint, "kisa-os-command-exec", "입력데이터 검증", "명령어 삽입", "CWE-78", severity,
                "src/A.java", 5, 5, "메시지", "snippet", 1, traceSafety, traceSafety == null ? null : "근거1\n근거2",
                aiContext, aiContext == null ? null : 3);
    }

    private static SecureCodeFinding finding(long appId, DetectedFinding d) {
        return SecureCodeFinding.detect(appId, d, NOW);
    }

    @Test
    void 추가_규칙은_등급과_무관하게_대상이다() {
        // 난수·XXE는 MEDIUM이지만 "무엇에 쓰는가"를 코드에서 읽어야 판단되는 규칙이라 넣는다
        assertThat(service.isTarget("kisa-insecure-random", "MEDIUM", null)).isTrue();
        assertThat(service.isTarget("kisa-xxe-parser", "MEDIUM", null)).isTrue();
        // 추가 규칙이 아닌 LOW는 대상 아님
        assertThat(service.isTarget("kisa-empty-catch", "LOW", null)).isFalse();
    }

    @Test
    void HIGH_MEDIUM은_추적이_확정했어도_대상이고_안전_확정만_뺀다() {
        assertThat(service.isTarget(RULE, "HIGH", null)).isTrue();
        assertThat(service.isTarget(RULE, "MEDIUM", null)).isTrue();
        assertThat(service.isTarget(RULE, "HIGH", "UNKNOWN")).isTrue();
        // 출처는 요청값으로 확정이어도 그 뒤의 검증(허용 목록·정규화 후 기준 폴더 검사)은 엔진이 보지 않는다 — AI가 본다.
        assertThat(service.isTarget(RULE, "HIGH", "CLIENT")).isTrue();
        assertThat(service.isTarget(RULE, "HIGH", "BYPASSABLE")).isTrue();
        // 안전 확정은 다시 묻지 않는다 — 기준 등급을 LOW까지 넓혀도 마찬가지.
        assertThat(service.isTarget(RULE, "LOW", "SERVER_SET")).isFalse();
        assertThat(service.isTarget(RULE, "LOW", "SESSION_OVERWRITE")).isFalse();
        assertThat(service.isTarget(RULE, "LOW", "XML_FIXED")).isFalse();
        ReflectionTestUtils.setField(service, "severities", List.of("HIGH", "MEDIUM", "LOW"));
        assertThat(service.isTarget(RULE, "LOW", "SERVER_SET")).isFalse();
        ReflectionTestUtils.setField(service, "severities", List.of("HIGH", "MEDIUM"));
        assertThat(service.isTarget(RULE, "LOW", null)).isFalse();
        assertThat(service.isTarget(RULE, null, null)).isFalse();
    }

    /** 판정 불가는 MEDIUM이라 예전엔 기본 기준(HIGH)에 안 걸려 AI도 엔진도 보지 않은 채 남았다. */
    @Test
    void 연계_추적이_판정_불가로_남긴_탐지는_등급과_무관하게_대상이다() {
        assertThat(service.isTarget("kisa-os-command-exec", "MEDIUM", "UNKNOWN")).isTrue();
        assertThat(service.isTarget("kisa-os-command-exec", "LOW", "UNKNOWN")).isTrue();
        // 비밀값 규칙은 판정 불가여도 보내지 않는다(값이 가려져 근거가 없다).
        assertThat(service.isTarget("kisa-hardcoded-secret-java", "MEDIUM", "UNKNOWN")).isFalse();
    }

    @Test
    void 비밀값_규칙은_값이_가려져_판단할_근거가_없어_대상이_아니고_남은_판별도_숨긴다() {
        assertThat(service.isTarget("kisa-hardcoded-secret-config", "HIGH", null)).isFalse();
        assertThat(service.isTarget("kisa-hardcoded-secret-java", "HIGH", null)).isFalse();

        SecureCodeFinding f = finding(1L, new DetectedFinding("s", "kisa-hardcoded-secret-config", "보안기능", "하드코드된 중요정보",
                "CWE-798", "HIGH", "app.properties", 3, 3, "메시지", "db.password=****", 3, null, null, null, null));
        f.applyAiReview("VULNERABLE", "high", "이유", SecureCodeAiReviewService.toTarget(f).inputHash(), NOW);
        when(findingRepository.findAiReviewCandidates(any())).thenReturn(List.of(f));

        assertThat(SecureCodeAiReviewService.isReviewCurrent(f)).isFalse();
        assertThat(service.getPendingTargets()).isEmpty();
    }

    @Test
    void 대기열은_후보_중_대상이_아니거나_판별을_마친_건을_뺀다() {
        // OPEN·지워진 앱·코드 문맥 조건은 쿼리가 한다(SecureCodeFindingRepositoryTest).
        SecureCodeFinding target = finding(1L, detected("a", "HIGH", null, "ctx-a"));
        SecureCodeFinding traced = finding(1L, detected("b", "HIGH", "CLIENT", "ctx-b"));
        SecureCodeFinding serverSet = finding(1L, detected("f", "LOW", "SERVER_SET", "ctx-f"));
        SecureCodeFinding reviewed = finding(1L, detected("e", "HIGH", null, "ctx-e"));
        reviewed.applyAiReview("NOT_VULNERABLE", "high", "이유", SecureCodeAiReviewService.toTarget(reviewed).inputHash(), NOW);
        when(findingRepository.findAiReviewCandidates(any())).thenReturn(List.of(target, traced, serverSet, reviewed));

        List<SecureCodeReviewTarget> pending = service.getPendingTargets();

        // 클라이언트 값 확정(HIGH)은 그 뒤의 검증을 보러 들어가고, 안전 확정(LOW)은 빠진다.
        assertThat(pending).extracting(SecureCodeReviewTarget::code).containsExactly("ctx-a", "ctx-b");
        assertThat(pending.get(1).traceLabel()).isEqualTo("클라이언트 값");
        assertThat(pending.get(0).codeStartLine()).isEqualTo(3);
    }

    @Test
    void 재점검으로_코드가_바뀌면_옛_판별은_숨겨지고_다시_대기다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", null, "old code"));
        f.applyAiReview("VULNERABLE", "medium", "이유", SecureCodeAiReviewService.toTarget(f).inputHash(), NOW);
        assertThat(SecureCodeAiReviewService.isReviewCurrent(f)).isTrue();

        f.redetect(detected("a", "HIGH", null, "new code"), NOW);
        when(findingRepository.findAiReviewCandidates(any())).thenReturn(List.of(f));

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
    void 관련_코드를_같이_보내고_비밀값을_가리며_입력_해시에_넣는다() {
        DetectedFinding base = detected("a", "HIGH", null, "ctx");
        String related = "[{\"path\":\"p/H.java\",\"startLine\":3,\"code\":\"String u = \\\"jdbc:mysql://h/db?password=hunter2\\\";\\nreturn \\\"bar\\\";\",\"reason\":\"탐지 메서드가 부르는 H.v()\"}]";
        SecureCodeFinding without = finding(1L, base);
        SecureCodeFinding with = finding(1L, base.withAiRelated(related));

        SecureCodeReviewTarget target = SecureCodeAiReviewService.toTarget(with);

        assertThat(target.relatedCode()).singleElement().satisfies(r -> {
            assertThat(r.path()).isEqualTo("p/H.java");
            assertThat(r.code()).contains("return \"bar\";").doesNotContain("hunter2");
        });
        // 관련 코드가 바뀌면 다시 판별 대기가 되도록 해시가 달라진다. 관련 코드가 없으면 예전과 같은 해시(기존 판별 유지).
        assertThat(target.inputHash()).isNotEqualTo(SecureCodeAiReviewService.toTarget(without).inputHash());
        assertThat(SecureCodeAiReviewService.toTarget(without).relatedCode()).isEmpty();
    }

    private static SecureCodeReviewRequest req(String verdict, String confidence, String reasoning, String hash) {
        return new SecureCodeReviewRequest(verdict, confidence, "요약", reasoning, "pgmID=../../x 로 상위 폴더에 쓴다", "pgmID를 영숫자로 검증", hash);
    }

    @Test
    void 앱을_넘겨_후보를_받고_상한만큼_가져온다() {
        // 앱 조건·정렬은 쿼리가 한다(SecureCodeFindingRepositoryTest) — 여기선 넘긴 앱과 건수 상한만 본다.
        SecureCodeFinding medium = finding(1L, detected("m", "MEDIUM", null, "ctx-m"));
        SecureCodeFinding high = finding(1L, detected("h", "HIGH", null, "ctx-h"));
        SecureCodeFinding otherApp = finding(2L, detected("o", "HIGH", null, "ctx-o"));
        when(findingRepository.findAiReviewCandidates(1L)).thenReturn(List.of(high, medium));
        when(findingRepository.findAiReviewCandidates(2L)).thenReturn(List.of(otherApp));
        when(findingRepository.findAiReviewCandidates(null)).thenReturn(List.of(high, otherApp, medium));

        assertThat(service.getPendingTargets(1L, null)).extracting(SecureCodeReviewTarget::code).containsExactly("ctx-h", "ctx-m");
        assertThat(service.getPendingTargets(1L, 1)).extracting(SecureCodeReviewTarget::code).containsExactly("ctx-h");
        assertThat(service.getPendingTargets(null, null)).hasSize(3);   // 앱을 안 주면(사람이 직접 돌림) 전체
        // 요청한 건수가 커도 1회 상한을 넘지 않는다.
        ReflectionTestUtils.setField(service, "maxPerRun", 2);
        assertThat(service.getPendingTargets(null, 100)).hasSize(2);
        assertThat(service.hasPendingTargets(2L)).isTrue();
    }

    @Test
    void 같은_입력으로_상한만큼_실패하면_대기에서_빼고_입력이_바뀌면_다시_센다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", null, "ctx-a"));
        when(findingRepository.findAiReviewCandidates(any())).thenReturn(List.of(f));
        when(findingRepository.findById(7L)).thenReturn(Optional.of(f));
        String hash = SecureCodeAiReviewService.toTarget(f).inputHash();

        service.recordFailure(7L, new SecureCodeReviewFailure(hash, "응답이 잘렸습니다"));
        service.recordFailure(7L, new SecureCodeReviewFailure(hash, "응답이 잘렸습니다"));
        assertThat(service.getPendingTargets()).hasSize(1);     // 2회 — 아직 다시 보낸다
        service.recordFailure(7L, new SecureCodeReviewFailure(hash, "취약 판별에 예상 공격·조치 방법이 없습니다"));

        assertThat(f.getAiFailCount()).isEqualTo(3);
        assertThat(service.getPendingTargets()).isEmpty();      // 3회 — 배치마다 재과금하지 않게 뺀다
        assertThat(service.isReviewGivenUp(f)).isTrue();
        assertThat(f.getAiLastError()).contains("예상 공격");

        // 재점검으로 입력이 바뀐 실패는 처음부터 센다.
        service.recordFailure(7L, new SecureCodeReviewFailure("other-hash", "x"));
        assertThat(f.getAiFailCount()).isEqualTo(1);
        // 판별이 저장되면 실패 기록을 지운다.
        f.applyAiReview("VULNERABLE", "high", "요약", "이유", "공격", "조치", hash, NOW);
        assertThat(f.getAiFailCount()).isNull();
        assertThatThrownBy(() -> service.recordFailure(7L, new SecureCodeReviewFailure(" ", "x")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** CKEditor pgmID 모양 — 한 요청값이 폴더 만들기·파일 쓰기 두 지점에 들어간다. AI는 한 번만, 결과는 두 지점 모두에. */
    @Test
    void 같은_출처는_한_번만_판별하고_결과를_함께_저장한다() {
        String evidence = "CkEditorController.java:51 요청 값 request.getParameter(\"pgmID\")\nFrameFileUtil.java:46 new File(dir)";
        SecureCodeFinding mkdir = finding(1L, new DetectedFinding("d", "kisa-path-traversal-dynamic-path", "입력", "경로", "CWE-22", "HIGH",
                "F.java", 46, 46, "m", "s", 40, "CLIENT", evidence, "ctx-mkdir", 40));
        SecureCodeFinding write = finding(1L, new DetectedFinding("w", "kisa-path-traversal-dynamic-path", "입력", "경로", "CWE-22", "HIGH",
                "F.java", 88, 88, "m", "s", 80, "CLIENT",
                evidence.replace("FrameFileUtil.java:46 new File(dir)", "FrameFileUtil.java:88 new File(path)"),
                String.join("\n", java.util.Collections.nCopies(20, "line")), 80));
        // 출처는 같지만 CWE가 다르면(같은 값이 SQL에도) 따로 판별한다.
        SecureCodeFinding sql = finding(1L, new DetectedFinding("q", "kisa-sql-injection-java-concat", "입력", "SQL", "CWE-89", "HIGH",
                "Q.java", 9, 9, "m", "s", 1, "CLIENT", evidence, "ctx-sql", 1));
        ReflectionTestUtils.setField(mkdir, "id", 1L);
        ReflectionTestUtils.setField(write, "id", 2L);
        ReflectionTestUtils.setField(sql, "id", 3L);
        when(findingRepository.findAiReviewCandidates(any())).thenReturn(List.of(mkdir, write, sql));

        List<SecureCodeReviewTarget> pending = service.getPendingTargets();

        assertThat(pending).extracting(SecureCodeReviewTarget::id).containsExactly(1L, 3L);
        SameOriginMember member = pending.get(0).sameOrigin().get(0);
        assertThat(member.id()).isEqualTo(2L);
        assertThat(member.sink()).isEqualTo("FrameFileUtil.java:88 new File(path)");
        // 위험 호출 앞뒤 줄만 싣는다(메서드 전체가 아니라).
        assertThat(member.code().split("\n")).hasSize(SecureCodeAiReviewService.SAME_ORIGIN_CONTEXT_LINES * 2 + 1);
        assertThat(pending.get(1).sameOrigin()).isEmpty();

        when(findingRepository.findById(1L)).thenReturn(Optional.of(mkdir));
        when(findingRepository.findById(2L)).thenReturn(Optional.of(write));
        when(findingRepository.findById(3L)).thenReturn(Optional.of(sql));
        service.saveReview(1L, new SecureCodeReviewRequest("VULNERABLE", "high", "요약", "- 근거", "공격", "조치",
                pending.get(0).inputHash(), List.of(new SameOriginRef(2L, member.inputHash()), new SameOriginRef(3L, "h-sql"))));

        assertThat(write.getAiVerdict()).isEqualTo("VULNERABLE");
        assertThat(SecureCodeAiReviewService.isReviewCurrent(write)).isTrue();   // 자기 입력 해시로 저장
        assertThat(sql.getAiVerdict()).isNull();                                 // 출처가 다른 id는 받지 않는다
        assertThat(service.getPendingTargets()).extracting(SecureCodeReviewTarget::id).containsExactly(3L);
    }

    @Test
    void 판별_값을_검증하고_저장한다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", null, "ctx"));
        when(findingRepository.findById(7L)).thenReturn(Optional.of(f));

        service.saveReview(7L, new SecureCodeReviewRequest("NOT_VULNERABLE", "high", " 상수 경로라 안전 ", "  - 12줄: 상수만 들어간다  ",
                "", " ", "hash"));

        assertThat(f.getAiVerdict()).isEqualTo("NOT_VULNERABLE");
        assertThat(f.getAiSummary()).isEqualTo("상수 경로라 안전");
        assertThat(f.getAiReasoning()).isEqualTo("- 12줄: 상수만 들어간다");
        // 취약하지 않으면 공격·조치는 빈 값으로 오고 null로 저장한다.
        assertThat(f.getAiAttack()).isNull();
        assertThat(f.getAiFix()).isNull();
        assertThat(f.getAiInputHash()).isEqualTo("hash");
        // 처리여부는 사람이 정한다 — AI가 오탐이라 해도 OPEN 그대로.
        assertThat(f.getStatus()).isEqualTo("OPEN");
    }

    @Test
    void 취약_판별은_예상_공격과_조치_방법까지_저장하고_없으면_거절한다() {
        SecureCodeFinding f = finding(1L, detected("a", "HIGH", "CLIENT", "ctx"));
        when(findingRepository.findById(7L)).thenReturn(Optional.of(f));

        service.saveReview(7L, req("VULNERABLE", "high", "- 51줄: 요청값", "hash"));

        assertThat(f.getAiAttack()).isEqualTo("pgmID=../../x 로 상위 폴더에 쓴다");
        assertThat(f.getAiFix()).isEqualTo("pgmID를 영숫자로 검증");
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high", "요약", "이유", "", "고친다", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high", " ", "이유", "공격", "고친다", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high",
                "가".repeat(SecureCodeAiReviewService.MAX_SUMMARY_LENGTH + 1), "이유", "공격", "고친다", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, new SecureCodeReviewRequest("VULNERABLE", "high", "요약", "이유",
                "가".repeat(SecureCodeAiReviewService.MAX_DETAIL_LENGTH + 1), "고친다", "h")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 잘못된_판별_요청은_거절한다() {
        when(findingRepository.findById(7L)).thenReturn(Optional.of(finding(1L, detected("a", "HIGH", null, "ctx"))));

        assertThatThrownBy(() -> service.saveReview(7L, req("SAFE", "high", "이유", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, req("VULNERABLE", "certain", "이유", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, req("VULNERABLE", "high", " ", "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, req("VULNERABLE", "high",
                "가".repeat(SecureCodeAiReviewService.MAX_REASONING_LENGTH + 1), "h")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(7L, req("VULNERABLE", "high", "이유", null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.saveReview(8L, req("VULNERABLE", "high", "이유", "h")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
