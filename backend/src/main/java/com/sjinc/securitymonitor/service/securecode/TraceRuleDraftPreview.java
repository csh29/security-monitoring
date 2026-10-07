package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.service.securecode.TraceRuleDrafter.Draft;
import com.sjinc.securitymonitor.service.securecode.TraceRuleDrafter.Evidenced;
import com.sjinc.securitymonitor.service.securecode.TraceRuleDrafter.OverwriteCandidate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * 추적 규칙 초안을 지금 설정(trace-rules.yml)과 비교하고, 초안을 반영했을 때 ${} 판정이 어떻게 바뀌는지 미리 계산한다.
 * 사람이 초안을 반영할지 정하는 근거다 — 바뀌는 판정이 0이면 그 항목은 이 앱에 효과가 없다.
 */
public final class TraceRuleDraftPreview {

    /** 초안 항목 하나와 지금 설정 대비 상태. */
    public record Item(String kind, String value, Status status, String detail, List<String> evidence) {
    }

    public enum Status {
        NEW("신규"), SAME("이미 있음"), DIFFERENT("다름"), UNUSABLE("직접 확인");

        private final String label;

        Status(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** 초안 반영 전후로 판정이 바뀐 ${} 한 곳. */
    public record Change(String path, int line, String expr, TraceSafety before, TraceSafety after) {
    }

    private TraceRuleDraftPreview() {
    }

    public static List<Item> compare(TraceRules current, Draft draft) {
        List<Item> items = new ArrayList<>();
        for (OverwriteCandidate c : draft.overwrites()) {
            String value = "@" + c.annotation() + (c.container() == null ? "" : " → " + c.container());
            List<String> evidence = new ArrayList<>(c.evidence());
            c.keys().forEach(k -> evidence.add(k.value() + " ← " + k.evidence()));
            c.nonSessionKeys().forEach(k -> evidence.add(k.value() + " (세션 값 아님) ← " + k.evidence()));
            if (!usable(c)) {
                items.add(new Item("세션 덮어쓰기", value, Status.UNUSABLE,
                        c.keys().isEmpty() ? "세션 값으로 덮어쓰는 키가 없습니다" : "덮어쓰는 위치가 두 단계 이상이라 설정으로 표현할 수 없습니다", evidence));
                continue;
            }
            TraceRules.SessionOverwrite existing = find(current, c);
            Set<String> keys = keys(c);
            if (existing == null) {
                items.add(new Item("세션 덮어쓰기", value, Status.NEW, "키 " + keys, evidence));
            } else if (existing.keys().equals(keys) && Objects.equals(existing.requiredFirstParam(), c.requiredFirstParam())) {
                items.add(new Item("세션 덮어쓰기", value, Status.SAME, "지금 설정(" + existing.name() + ")과 같습니다", evidence));
            } else {
                Set<String> added = new TreeSet<>(keys);
                added.removeAll(existing.keys());
                Set<String> removed = new TreeSet<>(existing.keys());
                removed.removeAll(keys);
                List<String> parts = new ArrayList<>();
                if (!added.isEmpty()) parts.add("추가 " + added);
                if (!removed.isEmpty()) parts.add("빠짐 " + removed + "(세션 값이 아니거나 코드에서 찾지 못함)");
                if (!Objects.equals(existing.requiredFirstParam(), c.requiredFirstParam())) {
                    parts.add("첫 파라미터 조건 " + existing.requiredFirstParam() + " → " + c.requiredFirstParam());
                }
                items.add(new Item("세션 덮어쓰기", value, Status.DIFFERENT, String.join(", ", parts), evidence));
            }
        }
        for (Evidenced e : draft.loginTypeNames()) {
            boolean covered = current.loginTypeNames().stream().anyMatch(e.value()::contains);
            items.add(new Item("로그인 정보 타입", e.value(), covered ? Status.SAME : Status.NEW,
                    covered ? "지금 설정의 이름 규칙에 이미 걸립니다" : "", List.of(e.evidence())));
        }
        for (Evidenced e : draft.loginMethodPrefixes()) {
            boolean covered = current.loginMethodPrefixes().stream().anyMatch(e.value()::startsWith);
            items.add(new Item("로그인 getter 접두어", e.value(), covered ? Status.SAME : Status.NEW,
                    covered ? "지금 설정의 접두어에 이미 걸립니다" : "", List.of(e.evidence())));
        }
        return items;
    }

    /** 지금 설정에 초안을 반영한 규칙. 같은 어노테이션·위치 항목은 초안으로 바꾸고, 없던 것은 더한다. */
    public static TraceRules merge(TraceRules current, Draft draft, String systemName) {
        Map<String, TraceRules.SessionOverwrite> overwrites = new LinkedHashMap<>();
        current.sessionOverwrites().forEach(o -> overwrites.put(o.annotation() + "|" + o.container(), o));
        for (OverwriteCandidate c : draft.overwrites()) {
            if (!usable(c)) continue;
            overwrites.put(c.annotation() + "|" + c.container(), new TraceRules.SessionOverwrite(
                    systemName + " @" + c.annotation(), c.annotation(), c.container(), c.requiredFirstParam(), keys(c)));
        }
        Set<String> prefixes = new LinkedHashSet<>(current.loginMethodPrefixes());
        draft.loginMethodPrefixes().forEach(e -> prefixes.add(e.value()));
        Set<String> types = new LinkedHashSet<>(current.loginTypeNames());
        draft.loginTypeNames().forEach(e -> types.add(e.value()));
        return new TraceRules(new ArrayList<>(overwrites.values()), prefixes, types, current.userScopeKeys());
    }

    /** 같은 ${}(경로·줄·식)의 판정이 바뀐 곳. 한 줄에 같은 식이 둘이면 순서로 맞춘다. */
    public static List<Change> changes(MybatisDollarTracer.Result before, MybatisDollarTracer.Result after) {
        Map<String, List<DollarVerdict>> beforeByKey = new LinkedHashMap<>();
        before.verdicts().forEach(v -> beforeByKey.computeIfAbsent(key(v), k -> new ArrayList<>()).add(v));
        Map<String, Integer> seen = new LinkedHashMap<>();
        List<Change> changes = new ArrayList<>();
        for (DollarVerdict v : after.verdicts()) {
            int index = seen.merge(key(v), 1, Integer::sum) - 1;
            List<DollarVerdict> candidates = beforeByKey.getOrDefault(key(v), List.of());
            if (index >= candidates.size()) continue;
            DollarVerdict old = candidates.get(index);
            if (old.safety() != v.safety()) {
                changes.add(new Change(v.path(), v.line(), v.expr(), old.safety(), v.safety()));
            }
        }
        return changes;
    }

    /**
     * 점검 완료 알림에 붙일 문구. 지금 설정과 같으면 null.
     * 예: "추적 규칙(trace-rules.yml)과 다른 항목 2개 — 세션 덮어쓰기 @AddUserInfo → paramData(다름: 빠짐 [regPgmId]), …
     *      반영하면 ${} 판정 3건이 바뀝니다. 초안은 서버 로그에 있습니다."
     */
    public static String note(List<Item> items, int changeCount) {
        List<Item> different = items.stream().filter(i -> i.status() != Status.SAME).toList();
        if (different.isEmpty()) return null;
        List<String> parts = different.stream()
                .map(i -> i.kind() + " " + i.value() + "(" + i.status().label() + (i.detail().isBlank() ? "" : ": " + i.detail()) + ")")
                .toList();
        return "추적 규칙(trace-rules.yml)과 다른 항목 " + different.size() + "개 — " + String.join(", ", parts)
                + ". 반영하면 ${} 판정 " + changeCount + "건이 바뀝니다. 초안은 서버 로그에 있으니 확인 후 반영하세요.";
    }

    private static String key(DollarVerdict v) {
        return v.path() + ":" + v.line() + ":" + v.expr();
    }

    private static boolean usable(OverwriteCandidate c) {
        return !c.keys().isEmpty() && (c.container() == null || !c.container().contains("."));
    }

    private static Set<String> keys(OverwriteCandidate c) {
        Set<String> keys = new LinkedHashSet<>();
        c.keys().forEach(k -> keys.add(k.value()));
        return keys;
    }

    private static TraceRules.SessionOverwrite find(TraceRules rules, OverwriteCandidate c) {
        for (TraceRules.SessionOverwrite o : rules.sessionOverwrites()) {
            if (o.annotation().equals(c.annotation()) && Objects.equals(o.container(), c.container())) return o;
        }
        return null;
    }
}
