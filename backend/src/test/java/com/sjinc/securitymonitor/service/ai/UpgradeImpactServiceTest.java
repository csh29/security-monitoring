package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.domain.UpgradeImpact;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest.BreakingChange;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest.Source;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UpgradeImpactServiceTest {

    private static final String WIKI = "https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.2-Release-Notes";

    private static UpgradeImpactRequest analyzed(String from, String to, String risk, String confidence,
                                                 List<Source> sources, List<BreakingChange> changes) {
        return new UpgradeImpactRequest("org.springframework.boot:spring-boot-starter-parent", from, to,
                UpgradeImpact.ANALYZED, risk, confidence, changes, List.of("파라미터 이름 컴파일 옵션 확인"),
                List.of("요청 파라미터 바인딩"), sources, null);
    }

    @Test
    void 근거_문서에_없는_출처를_단_breaking_change는_버리고_메모를_남긴다() {
        UpgradeImpactRequest request = analyzed("3.1.5", "3.2.12", "HIGH", "high",
                List.of(new Source("OFFICIAL_DOC", WIKI)),
                List.of(new BreakingChange("-parameters 없이 컴파일하면 파라미터 이름을 못 찾는다", WIKI, List.of()),
                        new BreakingChange("모델이 지어낸 항목", "https://example.com/made-up", List.of())));

        UpgradeImpactService.Normalized normalized = UpgradeImpactService.normalize(request);

        assertThat(normalized.breakingChanges()).extracting(BreakingChange::sourceUrl).containsExactly(WIKI);
        assertThat(normalized.note()).contains("1건");
    }

    @Test
    void 메이저_점프는_AI가_LOW라고_해도_HIGH로_본다() {
        UpgradeImpactRequest request = analyzed("2.7.18", "3.0.13", "LOW", "high",
                List.of(new Source("OFFICIAL_DOC", WIKI)), List.of());

        assertThat(UpgradeImpactService.normalize(request).risk()).isEqualTo("HIGH");
        assertThat(UpgradeImpactService.adjustRisk("LOW", "3.1.5", "3.2.12")).isEqualTo("LOW");
    }

    @Test
    void JIRA_이슈_목록만_근거면_신뢰도를_medium으로_낮춘다() {
        List<Source> jiraOnly = List.of(new Source("JIRA", "https://issues.apache.org/jira/issues/?jql=x"));
        List<Source> withDoc = List.of(new Source("JIRA", "https://issues.apache.org/jira/issues/?jql=x"),
                new Source("OFFICIAL_DOC", WIKI));

        assertThat(UpgradeImpactService.adjustConfidence("high", jiraOnly)).isEqualTo("medium");
        assertThat(UpgradeImpactService.adjustConfidence("low", jiraOnly)).isEqualTo("low");
        assertThat(UpgradeImpactService.adjustConfidence("high", withDoc)).isEqualTo("high");
    }

    @Test
    void 근거_없이_ANALYZED는_저장할_수_없다() {
        UpgradeImpactRequest request = analyzed("3.1.5", "3.2.12", "LOW", "high", List.of(), List.of());

        assertThatThrownBy(() -> UpgradeImpactService.normalize(request))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 정해지지_않은_출처_종류나_http가_아닌_주소는_근거로_치지_않는다() {
        UpgradeImpactRequest request = analyzed("3.1.5", "3.2.12", "LOW", "high",
                List.of(new Source("BLOG", "https://blog.example.com"), new Source("OFFICIAL_DOC", "file:///etc/passwd")),
                List.of());

        assertThatThrownBy(() -> UpgradeImpactService.normalize(request))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 근거를_못_찾은_건은_분석_필드를_모두_비운다() {
        UpgradeImpactRequest request = new UpgradeImpactRequest("org.apache.kafka:kafka-clients", "3.6.1", "3.7.0",
                UpgradeImpact.NO_SOURCE, "HIGH", "high",
                List.of(new BreakingChange("추측", "https://kafka.apache.org", List.of())), List.of("추측 조치"), List.of("x"),
                List.of(new Source("OFFICIAL_DOC", "https://kafka.apache.org")), "근거 문서를 찾지 못함");

        UpgradeImpactService.Normalized normalized = UpgradeImpactService.normalize(request);

        assertThat(normalized.status()).isEqualTo(UpgradeImpact.NO_SOURCE);
        assertThat(normalized.risk()).isNull();
        assertThat(normalized.breakingChanges()).isEmpty();
        assertThat(normalized.requiredActions()).isEmpty();
        assertThat(normalized.sources()).isEmpty();
        assertThat(normalized.note()).isEqualTo("근거 문서를 찾지 못함");
    }

    @Test
    void 대조용_이름은_공백_중복_문장을_걸러낸다() {
        assertThat(UpgradeImpactService.normalizeSymbols(java.util.Arrays.asList(
                " javax.servlet ", "javax.servlet", "", null, "이건 이름이 아니라 문장이다", "spring.redis")))
                .containsExactly("javax.servlet", "spring.redis");
        assertThat(UpgradeImpactService.normalizeSymbols(null)).isEmpty();
    }

    @Test
    void 정해지지_않은_상태값은_거절한다() {
        UpgradeImpactRequest request = new UpgradeImpactRequest("a:b", "1.0", "1.1", "DONE",
                null, null, null, null, null, null, null);

        assertThatThrownBy(() -> UpgradeImpactService.normalize(request))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
