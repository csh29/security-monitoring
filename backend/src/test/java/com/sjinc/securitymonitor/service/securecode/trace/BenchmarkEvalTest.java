package com.sjinc.securitymonitor.service.securecode.trace;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.SecureCodeSnippetBuilder;
import com.sjinc.securitymonitor.service.securecode.semgrep.RuleSetLoader;
import com.sjinc.securitymonitor.service.securecode.semgrep.SemgrepReportParser;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;

/**
 * 임시 측정용 — OWASP Benchmark 정답표와 "규칙 + 연계 추적" 판정을 대조한다. bench.dir이 없으면 돌지 않는다.
 * -Dbench.dir=BenchmarkJava 폴더 -Dbench.semgrep=규칙 결과 json -Dbench.rule=규칙 id -Dbench.category=정답표 범주
 */
@EnabledIfSystemProperty(named = "bench.dir", matches = ".+")
class BenchmarkEvalTest {

    @Test
    void 정답표와_대조() throws Exception {
        Path bench = Path.of(System.getProperty("bench.dir"));
        String ruleId = System.getProperty("bench.rule");
        String category = System.getProperty("bench.category");

        Map<String, Boolean> expected = new TreeMap<>();
        for (String line : Files.readAllLines(bench.resolve("expectedresults-1.2.csv"))) {
            String[] c = line.split(",");
            if (c.length >= 3 && !line.startsWith("#") && c[1].equals(category)) expected.put(c[0], c[2].equals("true"));
        }

        SemgrepReport report = new SemgrepReportParser(new ObjectMapper())
                .parse(Files.readString(Path.of(System.getProperty("bench.semgrep")), StandardCharsets.UTF_8));
        List<DetectedFinding> detected = new SecureCodeSnippetBuilder(bench).build(
                report.matches().stream().filter(m -> m.ruleId().equals(ruleId)).toList());

        Map<String, String> sources = new LinkedHashMap<>();
        try (Stream<Path> files = Files.walk(bench.resolve("src/main/java"))) {
            for (Path f : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".java"))::iterator) {
                sources.put(bench.relativize(f).toString().replace('\\', '/'), Files.readString(f, StandardCharsets.UTF_8));
            }
        }
        JavaSourceIndex java = JavaSourceIndex.fromSources(sources);
        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(java, TraceRules.empty(), new RuleSetLoader().load(Path.of(System.getProperty("bench.rules", "../securecode/rules"))).sinks()).trace(detected);

        Pattern test = Pattern.compile("(BenchmarkTest\\d+)\\.java$");
        Map<String, TraceSafety> worstByTest = new TreeMap<>();
        Map<String, List<String>> evidenceByTest = new TreeMap<>();
        for (SinkTracer.SinkVerdict v : verdicts) {
            Matcher m = test.matcher(v.path());
            if (!m.find()) continue;
            TraceSafety prev = worstByTest.get(m.group(1));
            if (prev == null || v.safety().worseThan(prev)) {
                worstByTest.put(m.group(1), v.safety());
                evidenceByTest.put(m.group(1), v.evidence());
            }
        }

        StringBuilder out = new StringBuilder();
        // "보고" = HIGH(클라이언트 값·우회 가능). 판정 불가(MEDIUM)는 따로 센다.
        int tp = 0, fp = 0, fn = 0, tn = 0, unknownReal = 0, unknownFake = 0, untraced = 0;
        Map<String, Integer> fnReasons = new TreeMap<>();
        Map<String, Integer> fpReasons = new TreeMap<>();
        List<String> fpTests = new java.util.ArrayList<>();
        for (Map.Entry<String, Boolean> e : expected.entrySet()) {
            TraceSafety s = worstByTest.get(e.getKey());
            if (s == null) untraced++;
            boolean reported = s != null && (s == TraceSafety.CLIENT || s == TraceSafety.BYPASSABLE);
            if (s == TraceSafety.UNKNOWN) {
                if (e.getValue()) unknownReal++; else unknownFake++;
            }
            if (e.getValue() && reported) tp++;
            else if (!e.getValue() && reported) {
                fp++;
                fpTests.add(e.getKey());
                fpReasons.merge(firstStep(evidenceByTest.get(e.getKey())), 1, Integer::sum);
            } else if (e.getValue()) {
                fn++;
                fnReasons.merge(s + " | " + firstStep(evidenceByTest.get(e.getKey())), 1, Integer::sum);
            } else tn++;
        }
        int real = tp + fn, fake = fp + tn;
        out.append(String.format("[%s / %s] 정답 취약 %d, 오탐 유도 %d, 추적 판정 없음 %d%n", category, ruleId, real, fake, untraced));
        out.append(String.format("  HIGH 보고: 정탐 %d, 오탐 %d / 미탐 %d, 정상 %d → 탐지율 %.1f%%, 오탐률 %.1f%%%n",
                tp, fp, fn, tn, 100.0 * tp / real, 100.0 * fp / fake));
        out.append(String.format("  판정 불가(MEDIUM): 실제 취약 %d, 오탐 유도 %d%n", unknownReal, unknownFake));
        out.append("  미탐 원인(판정 | 근거 첫 줄) 상위:\n");
        fnReasons.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(12)
                .forEach(x -> out.append("    " + x.getValue() + "  " + x.getKey() + "\n"));
        out.append("  오탐 원인(근거 첫 줄) 상위:\n");
        fpReasons.entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(8)
                .forEach(x -> out.append("    " + x.getValue() + "  " + x.getKey() + "\n"));
        out.append("  오탐 테스트: ").append(String.join(" ", fpTests)).append("\n");
        Files.writeString(Path.of(System.getProperty("bench.out")), out.toString(), StandardCharsets.UTF_8);
    }

    private static String firstStep(List<String> evidence) {
        if (evidence == null || evidence.isEmpty()) return "-";
        return evidence.get(0).replaceAll("BenchmarkTest\\d+", "T").replaceAll("\\.java:\\d+", ".java").replaceAll("\"[^\"]*\"", "\"…\"");
    }
}
