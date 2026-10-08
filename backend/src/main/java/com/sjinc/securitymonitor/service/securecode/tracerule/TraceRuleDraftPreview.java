package com.sjinc.securitymonitor.service.securecode.tracerule;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.sjinc.securitymonitor.dto.securecode.DollarVerdict;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.trace.MybatisDollarTracer;

/**
 * 확인 대기 중인 추적 규칙 변경을 반영했을 때 판정이 어떻게 바뀌는지 미리 계산한다(지금 규칙과 변경을 적용한 규칙으로 연계 추적을 두 번 돌린 차이).
 * 사람이 반영할지 정하는 근거다 — 바뀌는 판정이 0이면 그 변경은 이 앱에 효과가 없다.
 */
public final class TraceRuleDraftPreview {

    /** 반영 전후로 판정이 바뀐 한 곳({@code ${}} 또는 사용자 범위 키 {@code #{}}). */
    public record Change(String path, int line, String expr, TraceSafety before, TraceSafety after) {
    }

    private TraceRuleDraftPreview() {
    }

    /** 같은 위치(경로·줄·식)의 판정이 바뀐 곳. 한 줄에 같은 식이 둘이면 순서로 맞춘다. */
    public static List<Change> changes(MybatisDollarTracer.Result before, MybatisDollarTracer.Result after) {
        List<Change> changes = new ArrayList<>(changes(before.verdicts(), after.verdicts()));
        changes.addAll(changes(before.scopeVerdicts(), after.scopeVerdicts()));
        return changes;
    }

    private static List<Change> changes(List<DollarVerdict> before, List<DollarVerdict> after) {
        Map<String, List<DollarVerdict>> beforeByKey = new LinkedHashMap<>();
        before.forEach(v -> beforeByKey.computeIfAbsent(key(v), k -> new ArrayList<>()).add(v));
        Map<String, Integer> seen = new LinkedHashMap<>();
        List<Change> changes = new ArrayList<>();
        for (DollarVerdict v : after) {
            int index = seen.merge(key(v), 1, Integer::sum) - 1;
            List<DollarVerdict> candidates = beforeByKey.getOrDefault(key(v), List.of());
            if (index >= candidates.size()) {
                // 사용자 범위 키를 더하면 전에 없던 판정이 생긴다 — 위험한 판정만 탐지가 되므로 그것만 센다.
                if (!v.safety().isSafe()) {
                    changes.add(new Change(v.path(), v.line(), v.expr(), null, v.safety()));
                }
                continue;
            }
            DollarVerdict old = candidates.get(index);
            if (old.safety() != v.safety()) {
                changes.add(new Change(v.path(), v.line(), v.expr(), old.safety(), v.safety()));
            }
        }
        return changes;
    }

    private static String key(DollarVerdict v) {
        return v.path() + ":" + v.line() + ":" + v.expr();
    }
}
