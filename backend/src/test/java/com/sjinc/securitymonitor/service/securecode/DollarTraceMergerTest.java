package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DollarTraceMergerTest {

    private static final String RULE = DollarTraceMerger.RULE_ID;

    @Test
    void 판정별로_등급을_다시_매기고_근거를_붙인다() {
        List<DetectedFinding> detected = List.of(
                finding("fp1", RULE, "m.xml", 10),
                finding("fp2", RULE, "m.xml", 20),
                finding("fp3", RULE, "m.xml", 30),
                finding("fp4", RULE, "m.xml", 40));
        List<DollarVerdict> verdicts = List.of(
                verdict("m.xml", 10, TraceSafety.CLIENT),
                verdict("m.xml", 20, TraceSafety.BYPASSABLE),
                verdict("m.xml", 30, TraceSafety.UNKNOWN),
                verdict("m.xml", 40, TraceSafety.SESSION_OVERWRITE));

        DollarTraceMerger.Merged merged = DollarTraceMerger.merge(detected, verdicts);

        assertThat(merged.findings()).extracting(DetectedFinding::severity).containsExactly("HIGH", "HIGH", "MEDIUM", "LOW");
        assertThat(merged.findings()).extracting(DetectedFinding::traceSafety)
                .containsExactly("CLIENT", "BYPASSABLE", "UNKNOWN", "SESSION_OVERWRITE");
        assertThat(merged.findings().get(0).traceEvidence()).isEqualTo("출처\nm.xml:10");
        // 지문은 바뀌지 않는다 — 재점검 비교·사람의 처리여부가 유지돼야 한다.
        assertThat(merged.findings()).extracting(DetectedFinding::fingerprint).containsExactly("fp1", "fp2", "fp3", "fp4");
        assertThat(merged.traced()).isEqualTo(4);
        assertThat(merged.unmatched()).isZero();
    }

    @Test
    void 한_줄의_여러_달러중괄호는_등장_순서로_맞춘다() {
        List<DetectedFinding> detected = List.of(finding("a", RULE, "m.xml", 35), finding("b", RULE, "m.xml", 35));
        List<DollarVerdict> verdicts = List.of(verdict("m.xml", 35, TraceSafety.SERVER_SET), verdict("m.xml", 35, TraceSafety.CLIENT));

        List<DetectedFinding> merged = DollarTraceMerger.merge(detected, verdicts).findings();

        assertThat(merged).extracting(DetectedFinding::severity).containsExactly("LOW", "HIGH");
    }

    @Test
    void 줄_안의_개수가_다르면_추측하지_않고_Semgrep_등급을_둔다() {
        List<DetectedFinding> detected = List.of(finding("a", RULE, "m.xml", 5), finding("b", RULE, "m.xml", 5));
        List<DollarVerdict> verdicts = List.of(verdict("m.xml", 5, TraceSafety.SERVER_SET));

        DollarTraceMerger.Merged merged = DollarTraceMerger.merge(detected, verdicts);

        assertThat(merged.findings()).extracting(DetectedFinding::severity).containsExactly("HIGH", "HIGH");
        assertThat(merged.findings()).extracting(DetectedFinding::traceSafety).containsOnlyNulls();
        assertThat(merged.unmatched()).isEqualTo(2);
    }

    @Test
    void 다른_규칙의_탐지는_건드리지_않는다() {
        List<DetectedFinding> detected = List.of(finding("a", "kisa-insecure-random", "m.xml", 10));
        List<DollarVerdict> verdicts = List.of(verdict("m.xml", 10, TraceSafety.SERVER_SET));

        assertThat(DollarTraceMerger.merge(detected, verdicts).findings().get(0)).isEqualTo(detected.get(0));
    }

    private static DetectedFinding finding(String fingerprint, String ruleId, String path, int line) {
        return new DetectedFinding(fingerprint, ruleId, "분류", "SQL 삽입", "CWE-89", "HIGH", path, line, line,
                "메시지", "code", line, null, null, null, null);
    }

    private static DollarVerdict verdict(String path, int line, TraceSafety safety) {
        return new DollarVerdict(path, line, "t.q", "k", "k", safety, List.of("출처", path + ":" + line));
    }
}
