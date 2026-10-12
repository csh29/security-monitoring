package com.sjinc.securitymonitor.repository;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/** 화면 조회·AI 대기열 쿼리 — 지워진 앱 제외와 심각도 정렬을 쿼리가 한다(예전엔 서비스가 자바로 거르고 정렬했다). 메모리 H2로 실제 쿼리를 돌린다. */
@DataJpaTest
class SecureCodeFindingRepositoryTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 12, 9, 0);

    @Autowired
    private SecureCodeFindingRepository findingRepository;
    @Autowired
    private AppRepository appRepository;

    private Long crm;
    private Long test;

    @BeforeEach
    void setUp() {
        crm = appRepository.save(App.builder().systemName("CRM").build()).getId();
        test = appRepository.save(App.builder().systemName("TEST").build()).getId();
    }

    private SecureCodeFinding save(Long appId, String fingerprint, String severity, String file, int line, String aiContext) {
        DetectedFinding d = new DetectedFinding(fingerprint, "kisa-os-command-exec", "입력데이터 검증", "명령어 삽입", "CWE-78", severity,
                file, line, line, "메시지", "snippet", 1, null, null, aiContext, aiContext == null ? null : 1);
        return findingRepository.save(SecureCodeFinding.detect(appId, d, NOW));
    }

    @Test
    void 화면_조회는_지워진_앱을_빼고_심각도_높은_것부터_같은_등급은_앱_파일_줄_순이다() {
        save(crm, "a", "MEDIUM", "A.java", 1, null);
        save(crm, "b", "HIGH", "B.java", 9, null);
        save(crm, "c", "HIGH", "A.java", 5, null);
        save(crm, "d", "high", "A.java", 7, null);   // 대소문자는 가리지 않는다(SeverityOrder와 같다)
        save(crm, "e", "WEIRD", "A.java", 2, null);  // 모르는 값은 맨 뒤
        save(crm, "f", "CRITICAL", "Z.java", 1, null);
        save(999L, "g", "CRITICAL", "A.java", 1, null);  // 앱 관리에서 지워진 앱

        assertThat(findingRepository.search(null, null))
                .extracting(SecureCodeFinding::getFingerprint)
                .containsExactly("f", "c", "d", "b", "a", "e");
    }

    @Test
    void 화면_조회는_앱과_처리여부로_거른다() {
        save(crm, "a", "HIGH", "A.java", 1, null);
        save(test, "b", "HIGH", "A.java", 1, null);
        save(crm, "c", "HIGH", "C.java", 1, null).changeStatusManually("FALSE_POSITIVE", "tester", NOW);

        assertThat(findingRepository.search(crm, null)).extracting(SecureCodeFinding::getFingerprint).containsExactly("a", "c");
        assertThat(findingRepository.search(crm, "OPEN")).extracting(SecureCodeFinding::getFingerprint).containsExactly("a");
    }

    @Test
    void AI_대기열_후보는_OPEN_지워지지_않은_앱_코드_문맥_있음_높은_등급부터다() {
        SecureCodeFinding medium = save(crm, "m", "MEDIUM", "A.java", 1, "ctx-m");
        SecureCodeFinding high = save(crm, "h", "HIGH", "A.java", 2, "ctx-h");
        save(crm, "n", "HIGH", "A.java", 3, null);                          // 코드 문맥 없음 — 다음 점검까지 기다린다
        save(999L, "d", "HIGH", "A.java", 4, "ctx-d");                      // 지워진 앱
        save(crm, "x", "HIGH", "A.java", 5, "ctx-x").changeStatusManually("FALSE_POSITIVE", "tester", NOW);
        SecureCodeFinding other = save(test, "o", "HIGH", "A.java", 6, "ctx-o");

        assertThat(findingRepository.findAiReviewCandidates(null))
                .extracting(SecureCodeFinding::getId)
                .containsExactly(high.getId(), other.getId(), medium.getId());
        assertThat(findingRepository.findAiReviewCandidates(crm))
                .extracting(SecureCodeFinding::getId)
                .containsExactly(high.getId(), medium.getId());
    }
}
