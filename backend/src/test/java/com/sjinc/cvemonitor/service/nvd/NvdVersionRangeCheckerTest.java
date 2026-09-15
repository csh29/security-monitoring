package com.sjinc.cvemonitor.service.nvd;

import com.sjinc.cvemonitor.dto.nvd.NvdConfiguration;
import com.sjinc.cvemonitor.dto.nvd.NvdCpeMatch;
import com.sjinc.cvemonitor.dto.nvd.NvdNode;
import com.sjinc.cvemonitor.service.nvd.NvdVersionRangeChecker.MatchResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class NvdVersionRangeCheckerTest {

    private final NvdVersionRangeChecker checker = new NvdVersionRangeChecker();

    /** CVE-2026-47838(spring-security-web)와 같은 실제 형태: 5.7/5.8/6.3/6.4/6.5 브랜치만 있고
     * 6.2.x는 범위 목록에 없다 — description만 봤으면 놓쳤을 "브랜치 사이 공백" 케이스. */
    @Test
    void 브랜치_사이_공백에_있으면_false로_판단한다() {
        List<NvdConfiguration> configurations = configWithRanges(
                range("5.7.0", null, null, "5.7.25"),
                range("5.8.0", null, null, "5.8.27"),
                range("6.3.0", null, null, "6.3.18"),
                range("6.4.0", null, null, "6.4.18"),
                range("6.5.0", null, null, "6.5.11")
        );

        MatchResult result = checker.check(configurations, "6.2.4");

        assertThat(result.matched()).isFalse();
    }

    @Test
    void 범위_안에_있으면_true와_매치된_범위를_돌려준다() {
        List<NvdConfiguration> configurations = configWithRanges(
                range("6.1.0", null, null, "6.1.28")
        );

        MatchResult result = checker.check(configurations, "6.1.8");

        assertThat(result.matched()).isTrue();
        assertThat(result.matchedRange()).contains("6.1.0").contains("6.1.28");
    }

    @Test
    void Final_접미사가_붙어도_숫자_범위로_정상_비교한다() {
        List<NvdConfiguration> configurations = configWithRanges(
                range(null, null, null, "4.1.133.Final")
        );

        assertThat(checker.check(configurations, "4.1.110.Final").matched()).isTrue();
        assertThat(checker.check(configurations, "4.1.140.Final").matched()).isFalse();
    }

    @Test
    void 구조화된_범위_데이터가_없으면_null을_돌려준다() {
        assertThat(checker.check(null, "1.2.3").matched()).isNull();
        assertThat(checker.check(List.of(), "1.2.3").matched()).isNull();
    }

    @Test
    void vulnerable_true인_항목이_하나도_없으면_null을_돌려준다() {
        NvdCpeMatch notVulnerable = new NvdCpeMatch();
        notVulnerable.setVulnerable(false);
        notVulnerable.setVersionEndExcluding("1.0.0");
        NvdNode node = new NvdNode();
        node.setCpeMatch(List.of(notVulnerable));
        NvdConfiguration configuration = new NvdConfiguration();
        configuration.setNodes(List.of(node));

        assertThat(checker.check(List.of(configuration), "0.5.0").matched()).isNull();
    }

    private NvdCpeMatch range(String startIncluding, String startExcluding, String endIncluding, String endExcluding) {
        NvdCpeMatch match = new NvdCpeMatch();
        match.setVulnerable(true);
        match.setVersionStartIncluding(startIncluding);
        match.setVersionStartExcluding(startExcluding);
        match.setVersionEndIncluding(endIncluding);
        match.setVersionEndExcluding(endExcluding);
        return match;
    }

    private List<NvdConfiguration> configWithRanges(NvdCpeMatch... matches) {
        NvdNode node = new NvdNode();
        node.setOperator("OR");
        node.setCpeMatch(List.of(matches));
        NvdConfiguration configuration = new NvdConfiguration();
        configuration.setNodes(List.of(node));
        return List.of(configuration);
    }
}
