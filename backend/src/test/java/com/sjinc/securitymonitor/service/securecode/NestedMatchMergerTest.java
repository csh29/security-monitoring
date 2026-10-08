package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class NestedMatchMergerTest {

    private static SemgrepMatch m(String ruleId, int startLine, int startCol, int endLine, int endCol) {
        return new SemgrepMatch(ruleId, "분류", "항목", "CWE-22", "HIGH", "src/A.java", startLine, endLine, "설명", startCol, endCol);
    }

    private static DetectedFinding f(String fp, SemgrepMatch match) {
        return new DetectedFinding(fp, match.ruleId(), "분류", "항목", match.cwe(), match.severity(), match.filePath(),
                match.startLine(), match.endLine(), "설명", "code", match.startLine(), null, null, null, null);
    }

    /** OWASP Benchmark BenchmarkTest00001 — fis = new java.io.FileInputStream(new java.io.File(fileName)); */
    @Test
    void 같은_규칙이_안쪽에_겹쳐_걸리면_바깥_한_건만_남긴다() {
        SemgrepMatch outer = m("kisa-path-traversal-request", 72, 19, 72, 74);
        SemgrepMatch inner = m("kisa-path-traversal-request", 72, 47, 72, 73);

        DuplicateCweMerger.Merged merged = NestedMatchMerger.merge(List.of(outer, inner), List.of(f("o", outer), f("i", inner)));

        assertThat(merged.findings()).extracting(DetectedFinding::fingerprint).containsExactly("o");
        assertThat(merged.mergedAway()).containsExactly(Map.entry("i", "kisa-path-traversal-request"));
    }

    @Test
    void 여러_줄에_걸친_바깥_범위_안의_탐지도_합친다() {
        SemgrepMatch outer = m("r", 10, 9, 12, 30);
        SemgrepMatch inner = m("r", 11, 13, 11, 40);

        DuplicateCweMerger.Merged merged = NestedMatchMerger.merge(List.of(outer, inner), List.of(f("o", outer), f("i", inner)));

        assertThat(merged.findings()).extracting(DetectedFinding::fingerprint).containsExactly("o");
    }

    @Test
    void 나란히_걸리거나_규칙이_다르거나_열을_모르면_그대로_둔다() {
        List<SemgrepMatch> matches = List.of(
                m("kisa-sql-injection-mybatis-dollar", 3, 20, 3, 26),   // 한 줄의 ${a}
                m("kisa-sql-injection-mybatis-dollar", 3, 40, 3, 46),   // 한 줄의 ${b}
                m("kisa-path-traversal-request", 5, 10, 5, 60),
                m("kisa-path-traversal-download", 5, 20, 5, 50),         // 다른 규칙은 DuplicateCweMerger 몫
                new SemgrepMatch("u", "분류", "항목", "CWE-639", "HIGH", "src/A.java", 7, 7, "설명"),
                new SemgrepMatch("u", "분류", "항목", "CWE-639", "HIGH", "src/A.java", 7, 7, "설명"));
        List<DetectedFinding> detected = List.of(f("a", matches.get(0)), f("b", matches.get(1)), f("c", matches.get(2)),
                f("d", matches.get(3)), f("e", matches.get(4)), f("g", matches.get(5)));

        DuplicateCweMerger.Merged merged = NestedMatchMerger.merge(matches, detected);

        assertThat(merged.findings()).isEqualTo(detected);
        assertThat(merged.mergedAway()).isEmpty();
    }

    @Test
    void 범위가_똑같으면_앞의_것을_남긴다() {
        SemgrepMatch first = m("r", 4, 5, 4, 20);
        SemgrepMatch second = m("r", 4, 5, 4, 20);

        DuplicateCweMerger.Merged merged = NestedMatchMerger.merge(List.of(first, second), List.of(f("1", first), f("2", second)));

        assertThat(merged.findings()).extracting(DetectedFinding::fingerprint).containsExactly("1");
    }
}
