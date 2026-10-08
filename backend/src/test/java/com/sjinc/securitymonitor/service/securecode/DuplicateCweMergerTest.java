package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.service.securecode.trace.DollarTraceMerger;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DuplicateCweMergerTest {

    private static DetectedFinding f(String fp, String ruleId, String cwe, int line, String severity, String trace) {
        return new DetectedFinding(fp, ruleId, "분류", "항목", cwe, severity, "src/A.java", line, line, "설명", "code", line,
                trace, trace == null ? null : "근거", null, null);
    }

    @Test
    void 같은_줄_같은_CWE의_다른_규칙은_연계_추적_규칙_한_건으로_합친다() {
        DetectedFinding taint = f("t", "kisa-os-command-injection-request", "CWE-78", 82, "HIGH", null);
        DetectedFinding exec = f("e", "kisa-os-command-exec", "CWE-78", 82, "LOW", "SERVER_SET");
        DetectedFinding other = f("o", "kisa-insecure-random", "CWE-330", 82, "MEDIUM", null);

        DuplicateCweMerger.Merged merged = DuplicateCweMerger.merge(List.of(taint, exec, other));

        assertThat(merged.findings()).extracting(DetectedFinding::fingerprint).containsExactly("e", "o");
        assertThat(merged.findings().get(0).severity()).isEqualTo("LOW");   // 추적 판정이 있으면 그 등급
        assertThat(merged.findings().get(0).message()).contains("kisa-os-command-injection-request");
        assertThat(merged.mergedAway()).containsExactly(java.util.Map.entry("t", "kisa-os-command-exec"));
    }

    @Test
    void 남은_건에_추적_판정이_없으면_묶음에서_가장_높은_등급을_쓴다() {
        DetectedFinding a = f("a", "kisa-xss-a", "CWE-79", 5, "MEDIUM", null);
        DetectedFinding b = f("b", "kisa-xss-b", "CWE-79", 5, "HIGH", null);

        DuplicateCweMerger.Merged merged = DuplicateCweMerger.merge(List.of(b, a));

        assertThat(merged.findings()).singleElement().satisfies(x -> {
            assertThat(x.ruleId()).isEqualTo("kisa-xss-a");                 // 추적 규칙이 없으면 규칙 id 순 — 점검마다 같다
            assertThat(x.severity()).isEqualTo("HIGH");
        });
    }

    @Test
    void 같은_규칙이_한_줄에_여러_번이거나_줄이_다르거나_CWE가_없으면_합치지_않는다() {
        List<DetectedFinding> detected = List.of(
                f("d1", DollarTraceMerger.RULE_ID, "CWE-89", 3, "HIGH", "CLIENT"),
                f("d2", DollarTraceMerger.RULE_ID, "CWE-89", 3, "LOW", "SERVER_SET"),
                f("x", "kisa-os-command-exec", "CWE-78", 4, "LOW", "SERVER_SET"),
                f("y", "kisa-os-command-injection-request", "CWE-78", 5, "HIGH", null),
                f("n1", "r1", null, 6, "LOW", null),
                f("n2", "r2", null, 6, "LOW", null));

        DuplicateCweMerger.Merged merged = DuplicateCweMerger.merge(detected);

        assertThat(merged.findings()).isEqualTo(detected);
        assertThat(merged.mergedAway()).isEmpty();
    }
}
