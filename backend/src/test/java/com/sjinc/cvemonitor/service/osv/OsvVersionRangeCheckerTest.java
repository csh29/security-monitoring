package com.sjinc.cvemonitor.service.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.cvemonitor.dto.osv.OsvVulnDetail;
import com.sjinc.cvemonitor.service.osv.OsvVersionRangeChecker.MatchResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OsvVersionRangeCheckerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final OsvVersionRangeChecker checker = new OsvVersionRangeChecker();

    /**
     * 실제로 겪은 케이스를 그대로 재현한다: micrometer-core 1.12.6 / CVE-2026-40984를 NVD
     * description 프로즈("1.9.x", "1.13.x" 등)만 보고 "1.10~1.12는 공백"이라 잘못 판단했는데,
     * OSV의 구조화 데이터(GHSA-g3pr-3p32-fp23)엔 introduced:1.10.0, last_affected:1.13.15
     * 라는 범위가 명시돼 있어 1.12.6이 실제로 그 안에 포함된다.
     */
    @Test
    void 실제_micrometer_사례_설치버전이_lastAffected_범위_안이면_취약으로_판정한다() throws Exception {
        OsvVulnDetail detail = rangeDetail("io.micrometer:micrometer-core",
                "{\"introduced\": \"1.10.0\"}, {\"last_affected\": \"1.13.15\"}");

        MatchResult result = checker.check(List.of(detail), "io.micrometer", "micrometer-core", "1.12.6");

        assertThat(result.matched()).isTrue();
        assertThat(result.matchedRange()).isEqualTo(">= 1.10.0, <= 1.13.15");
    }

    @Test
    void 설치버전이_last_affected_범위보다_낮으면_취약아님으로_판정한다() throws Exception {
        OsvVulnDetail detail = rangeDetail("io.micrometer:micrometer-core",
                "{\"introduced\": \"1.10.0\"}, {\"last_affected\": \"1.13.15\"}");

        MatchResult result = checker.check(List.of(detail), "io.micrometer", "micrometer-core", "1.9.17");

        assertThat(result.matched()).isFalse();
    }

    @Test
    void fixed_이벤트는_배타적_상한이라_그_버전_자체는_취약아님이다() throws Exception {
        OsvVulnDetail detail = rangeDetail("com.example:lib",
                "{\"introduced\": \"0\"}, {\"fixed\": \"2.1.0\"}");

        MatchResult exact = checker.check(List.of(detail), "com.example", "lib", "2.1.0");
        MatchResult below = checker.check(List.of(detail), "com.example", "lib", "2.0.9");

        assertThat(exact.matched()).isFalse();
        assertThat(below.matched()).isTrue();
    }

    @Test
    void 여러_range가_있으면_그중_하나라도_걸리면_취약이다() throws Exception {
        String json = """
                {
                  "id": "GHSA-multi-range",
                  "affected": [
                    {"package": {"name": "com.example:lib", "ecosystem": "Maven"},
                     "ranges": [
                       {"events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]},
                       {"events": [{"introduced": "2.0.0"}, {"fixed": "2.3.0"}]}
                     ]}
                  ]
                }
                """;
        OsvVulnDetail detail = MAPPER.readValue(json, OsvVulnDetail.class);

        MatchResult result = checker.check(List.of(detail), "com.example", "lib", "2.1.0");

        assertThat(result.matched()).isTrue();
        assertThat(result.matchedRange()).isEqualTo(">= 2.0.0, < 2.3.0");
    }

    @Test
    void 수정버전_미공개로_열린_범위면_그_이후_전부_취약이다() throws Exception {
        OsvVulnDetail detail = rangeDetail("com.example:lib", "{\"introduced\": \"3.0.0\"}");

        MatchResult result = checker.check(List.of(detail), "com.example", "lib", "3.5.0");

        assertThat(result.matched()).isTrue();
        assertThat(result.matchedRange()).contains("수정 버전 미공개");
    }

    @Test
    void 다른_패키지의_range는_무시한다() throws Exception {
        OsvVulnDetail detail = rangeDetail("com.other:lib", "{\"introduced\": \"0\"}, {\"fixed\": \"9.9.9\"}");

        MatchResult result = checker.check(List.of(detail), "com.example", "lib", "1.0.0");

        assertThat(result.matched()).isNull();
    }

    @Test
    void 상세가_없으면_판단불가다() {
        MatchResult result = checker.check(List.of(), "com.example", "lib", "1.0.0");

        assertThat(result.matched()).isNull();
        assertThat(result).isEqualTo(MatchResult.UNKNOWN);
    }

    private OsvVulnDetail rangeDetail(String packageName, String eventsJson) throws Exception {
        String json = """
                {
                  "id": "GHSA-test",
                  "affected": [
                    {"package": {"name": "%s", "ecosystem": "Maven"},
                     "ranges": [{"events": [%s]}]}
                  ]
                }
                """.formatted(packageName, eventsJson);
        return MAPPER.readValue(json, OsvVulnDetail.class);
    }
}
