package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SeverityOrder;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.sjinc.securitymonitor.service.securecode.trace.DollarTraceMerger;
import com.sjinc.securitymonitor.service.securecode.trace.SinkTracer;
import com.sjinc.securitymonitor.service.securecode.trace.UserScopeFindings;

/**
 * 같은 파일·같은 줄·같은 CWE에 다른 규칙이 여럿 걸린 탐지를 한 건으로 합친다. 한 약점을 두 방식으로 보는 규칙 쌍이 있어서
 * (명령 실행: taint {@code kisa-os-command-injection-request} + 실행 호출 {@code kisa-os-command-exec}, SSRF·경로 조작도 같은 모양)
 * 서블릿처럼 한 메서드에서 끝나는 코드는 같은 줄이 두 건이 되고, 연계 추적을 받는 쪽만 판정이 붙어 한 줄에 HIGH·LOW가 엇갈렸다.
 *
 * <p>남길 규칙은 <b>점검마다 같아야</b> 한다 — 지문에 규칙 id가 들어가서, 남는 규칙이 바뀌면 재점검 때 "해결+신규"로 뒤섞인다. 그래서 탐지 결과
 * (판정 유무)가 아니라 규칙만 보고 고른다: 연계 추적을 받는 규칙 → 규칙 id 순. 남는 건이 추적 판정을 받지 못했으면 등급은 묶음에서 가장 높은 것으로
 * 둔다(빠진 규칙이 더 높게 봤을 수 있다) — 그러면 결정론으로 못 정한 높은 등급이라 AI 판별 대상이 된다.
 *
 * <p>같은 규칙이 한 줄에 여러 번 걸린 것(한 줄의 {@code ${a}}·{@code ${b}})은 값마다 판정이 달라 합치지 않는다. CWE가 없는 탐지도 합치지 않는다.
 */
public final class DuplicateCweMerger {

    private DuplicateCweMerger() {
    }

    /**
     * @param findings  합친 결과(원래 순서 유지)
     * @param mergedAway 합쳐져 빠진 탐지의 지문 → 남은 규칙 id. 이 지문의 기존 탐지는 "고쳐서 해결"이 아니라 합친 것이라 비고를 남긴다(SecureCodeReconciler)
     */
    public record Merged(List<DetectedFinding> findings, Map<String, String> mergedAway) {
    }

    /** 연계 추적을 받는 규칙인가(위험 호출 지점·MyBatis/iBatis 매퍼·사용자 범위). */
    static boolean traceable(String ruleId) {
        return SinkTracer.supports(ruleId) || DollarTraceMerger.RULE_ID.equals(ruleId)
                || DollarTraceMerger.IBATIS_RULE_ID.equals(ruleId) || UserScopeFindings.RULE_ID.equals(ruleId);
    }

    private static final Comparator<String> RULE_PRIORITY = Comparator
            .comparing((String ruleId) -> !traceable(ruleId))
            .thenComparing(Comparator.naturalOrder());

    public static Merged merge(List<DetectedFinding> detected) {
        Map<String, List<DetectedFinding>> groups = new LinkedHashMap<>();
        for (DetectedFinding f : detected) {
            if (f.cwe() == null || f.cwe().isBlank()) continue;
            groups.computeIfAbsent(f.filePath() + "|" + f.startLine() + "|" + f.cwe().trim(), k -> new ArrayList<>()).add(f);
        }

        Map<DetectedFinding, DetectedFinding> replace = new HashMap<>();
        Map<String, String> mergedAway = new LinkedHashMap<>();
        for (List<DetectedFinding> group : groups.values()) {
            Set<String> rules = new TreeSet<>(RULE_PRIORITY);
            group.forEach(f -> rules.add(f.ruleId()));
            if (rules.size() < 2) continue;
            String kept = rules.iterator().next();
            List<String> others = rules.stream().filter(r -> !r.equals(kept)).toList();
            String highest = group.stream().map(DetectedFinding::severity)
                    .min(Comparator.nullsLast(SeverityOrder.HIGH_FIRST)).orElse(null);
            for (DetectedFinding f : group) {
                if (!f.ruleId().equals(kept)) {
                    mergedAway.put(f.fingerprint(), kept);
                    replace.put(f, null);
                    continue;
                }
                String severity = f.traceSafety() == null ? highest : f.severity();
                replace.put(f, f.withMerged(severity, note(f.message(), others)));
            }
        }
        if (replace.isEmpty()) return new Merged(detected, Map.of());

        List<DetectedFinding> result = new ArrayList<>(detected.size());
        for (DetectedFinding f : detected) {
            if (!replace.containsKey(f)) {
                result.add(f);
            } else if (replace.get(f) != null) {
                result.add(replace.get(f));
            }
        }
        return new Merged(result, mergedAway);
    }

    /** 설명 끝에 함께 걸린 규칙을 남긴다(상세보기의 설명·조치에 보인다). 컬럼 길이(1000)를 넘지 않게. */
    private static String note(String message, List<String> others) {
        String suffix = " (같은 줄·같은 CWE로 함께 탐지된 규칙 " + String.join(", ", others) + "을 한 건으로 합침)";
        String base = message == null ? "" : message;
        String merged = base + suffix;
        return merged.length() <= 1000 ? merged : base.substring(0, Math.max(0, 1000 - suffix.length())) + suffix;
    }
}
