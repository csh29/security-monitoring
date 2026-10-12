package com.sjinc.securitymonitor.service.securecode.trace;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.sjinc.securitymonitor.dto.securecode.DollarVerdict;

/**
 * Semgrep의 MyBatis {@code ${}} 탐지에 연계 추적 판정을 (파일, 줄, 줄 안 등장 순서)로 맞춰 붙이고 심각도를 다시 매긴다.
 * 줄 안 개수가 서로 다르면 추측하지 않고 Semgrep 등급(HIGH)을 그대로 둔다 — 모르면 위험한 쪽으로.
 * 안전 판정도 자동 오탐 처리하지 않는다 — 추적기가 틀렸을 때 사람이 근거를 보고 바로잡아야 한다.
 */
public final class DollarTraceMerger {

    /** 연계 추적 대상 규칙(securecode/rules/sql-injection.yml). */
    public static final String RULE_ID = "kisa-sql-injection-mybatis-dollar";
    /** iBatis 2의 $값$ — 같은 엔진(MybatisDollarTracer)이 sqlMap을 읽어 판정한다. */
    public static final String IBATIS_RULE_ID = "kisa-sql-injection-ibatis-dollar";
    /** 이 병합기가 판정을 붙이는 규칙들. */
    public static final java.util.Set<String> RULE_IDS = java.util.Set.of(RULE_ID, IBATIS_RULE_ID);

    /**
     * @param findings  판정을 붙인 탐지 목록(입력과 같은 순서)
     * @param traced    판정을 붙인 ${} 탐지 수
     * @param unmatched 판정을 붙이지 못한 ${} 탐지 수(줄 안 개수가 달랐다)
     */
    public record Merged(List<DetectedFinding> findings, int traced, int unmatched) {
    }

    private DollarTraceMerger() {
    }

    public static Merged merge(List<DetectedFinding> detected, List<DollarVerdict> verdicts) {
        Map<String, List<DollarVerdict>> verdictsByLine = new HashMap<>();
        for (DollarVerdict v : verdicts) {
            verdictsByLine.computeIfAbsent(v.path() + ":" + v.line(), k -> new ArrayList<>()).add(v);
        }
        Map<String, List<Integer>> findingsByLine = new LinkedHashMap<>();
        for (int i = 0; i < detected.size(); i++) {
            DetectedFinding f = detected.get(i);
            if (RULE_IDS.contains(f.ruleId())) {
                findingsByLine.computeIfAbsent(f.filePath() + ":" + f.startLine(), k -> new ArrayList<>()).add(i);
            }
        }

        List<DetectedFinding> result = new ArrayList<>(detected);
        int traced = 0, unmatched = 0;
        for (Map.Entry<String, List<Integer>> entry : findingsByLine.entrySet()) {
            List<Integer> indexes = entry.getValue();
            List<DollarVerdict> lineVerdicts = verdictsByLine.getOrDefault(entry.getKey(), List.of());
            if (lineVerdicts.size() != indexes.size()) {
                unmatched += indexes.size();
                continue;
            }
            for (int i = 0; i < indexes.size(); i++) {
                DetectedFinding f = result.get(indexes.get(i));
                DollarVerdict v = lineVerdicts.get(i);
                result.set(indexes.get(i), f.withTrace(v.safety().severity(), v.safety().name(),
                        String.join("\n", v.evidence())));
                traced++;
            }
        }
        return new Merged(result, traced, unmatched);
    }
}
