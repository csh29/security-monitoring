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
import com.sjinc.securitymonitor.service.securecode.trace.UserScopeFindings;

/**
 * 같은 파일·줄·CWE에 다른 규칙이 여럿 걸린 탐지를 한 건으로 합친다(한 약점을 taint·호출 두 방식으로 보는 규칙 쌍 때문).
 * 지문에 규칙 id가 들어가 재점검마다 같은 규칙이 남도록 규칙만 보고 고르며(연계 추적 규칙 → id 순), 추적 판정이 없으면 묶음의 최고 등급을 둔다.
 * 같은 규칙의 여러 값·CWE 없는 탐지는 값마다 판정이 달라 합치지 않는다.
 */
public final class DuplicateCweMerger {

    private DuplicateCweMerger() {
    }

    /**
     * @param findings  합친 결과(원래 순서 유지)
     * @param mergedAway 빠진 탐지의 지문 → 남은 규칙 id(해결이 아니라 합친 것으로 비고를 남긴다)
     */
    public record Merged(List<DetectedFinding> findings, Map<String, String> mergedAway) {
    }

    /** 연계 추적을 받는 규칙인가(위험 호출 지점 — 규칙 파일의 metadata.trace, MyBatis/iBatis 매퍼·사용자 범위). */
    static boolean traceable(String ruleId, Set<String> sinkRuleIds) {
        return sinkRuleIds.contains(ruleId) || DollarTraceMerger.RULE_ID.equals(ruleId)
                || DollarTraceMerger.IBATIS_RULE_ID.equals(ruleId) || UserScopeFindings.RULE_ID.equals(ruleId);
    }

    /** @param sinkRuleIds 위험 호출 지점 연계 추적을 받는 규칙 id(RuleSetLoader.RuleSet.sinks의 키) */
    public static Merged merge(List<DetectedFinding> detected, Set<String> sinkRuleIds) {
        Comparator<String> rulePriority = Comparator
                .comparing((String ruleId) -> !traceable(ruleId, sinkRuleIds))
                .thenComparing(Comparator.naturalOrder());
        Map<String, List<DetectedFinding>> groups = new LinkedHashMap<>();
        for (DetectedFinding f : detected) {
            if (f.cwe() == null || f.cwe().isBlank()) continue;
            groups.computeIfAbsent(f.filePath() + "|" + f.startLine() + "|" + f.cwe().trim(), k -> new ArrayList<>()).add(f);
        }

        Map<DetectedFinding, DetectedFinding> replace = new HashMap<>();
        Map<String, String> mergedAway = new LinkedHashMap<>();
        for (List<DetectedFinding> group : groups.values()) {
            Set<String> rules = new TreeSet<>(rulePriority);
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
