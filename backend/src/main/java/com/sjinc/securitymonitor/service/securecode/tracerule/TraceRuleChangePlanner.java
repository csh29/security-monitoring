package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleChange.Type;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.Draft;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.Evidenced;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.OverwriteCandidate;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.SessionOverwrite;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 추적 규칙 초안(TraceRuleDrafter)을 지금 설정과 비교해 trace-rules.yml에 할 변경을 만들고, 바로 반영할 것과 사람에게 물을 것을 가른다.
 *
 * <p>가르는 기준은 "잘못 반영했을 때 무엇을 잃는가"다(TraceRuleChange.Type.automatic).
 * <ul>
 *   <li>바로 반영 — 판정을 엄격하게 하는 변경(코드에서 세션 값이 아닌 값을 넣는 것으로 확인된 키 빼기)과 판정에 쓰지 않는 기록(프레임워크 구조).
 *       틀려도 오탐이 늘 뿐 위험을 놓치지 않는다.</li>
 *   <li>확인 대기 — 판정을 느슨하게 하는 변경(새 장치·키·로그인 정보 이름). 틀리면 진짜 취약점이 조용히 LOW가 된다.
 *       사용자 범위 키 추가는 엄격한 쪽이지만 탐지가 한꺼번에 늘 수 있어 함께 묻는다.</li>
 * </ul>
 *
 * <p>규칙은 여러 시스템이 같이 쓴다. 다른 시스템에서 넣은 키를 이 저장소 코드에서 못 찾았다고 빼지 않는다 — 같은 어노테이션이라도
 * 시스템마다 넣는 키가 다를 수 있다. 빼는 것은 이 저장소 코드가 <b>세션 값이 아닌 값</b>을 넣는다고 확인된 키뿐이다.
 */
public final class TraceRuleChangePlanner {

    /** 변경 목록과 사람이 봐야 할 안내(설정으로 표현할 수 없는 장치 등). */
    public record Plan(List<TraceRuleChange> changes, List<String> notes) {

        public List<TraceRuleChange> automatic() {
            return changes.stream().filter(c -> c.type().automatic()).toList();
        }

        public List<TraceRuleChange> needsReview() {
            return changes.stream().filter(c -> !c.type().automatic()).toList();
        }
    }

    private TraceRuleChangePlanner() {
    }

    public static Plan plan(TraceRules current, Draft draft, String system) {
        Map<String, TraceRuleChange> changes = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>(draft.notes());
        for (OverwriteCandidate c : draft.overwrites()) {
            String target = "@" + c.annotation() + (c.container() == null ? "" : " → " + c.container());
            if (c.container() != null && c.container().contains(".")) {
                notes.add("세션 덮어쓰기 " + target + " — 덮어쓰는 위치가 두 단계 이상이라 설정으로 표현할 수 없습니다. 직접 확인하세요. "
                        + String.join(" / ", c.evidence()));
                continue;
            }
            SessionOverwrite existing = find(current, c);
            List<String> keys = values(c.keys());
            if (existing == null) {
                if (keys.isEmpty()) continue; // 세션 값을 넣지 않는 장치는 등록할 것이 없다.
                put(changes, new TraceRuleChange(Type.ADD_OVERWRITE, system, c.annotation(), c.container(), c.requiredFirstParam(),
                        keys, null, evidence(c.evidence(), c.keys(), c.nonSessionKeys())));
                continue;
            }
            List<String> added = keys.stream().filter(k -> !existing.keys().contains(k)).toList();
            if (!added.isEmpty()) {
                put(changes, new TraceRuleChange(Type.ADD_OVERWRITE_KEYS, system, c.annotation(), c.container(), null,
                        added, null, evidence(c.evidence(), only(c.keys(), added), List.of())));
            }
            List<Evidenced> notSession = c.nonSessionKeys().stream()
                    .filter(k -> existing.keys().contains(k.value()) && !keys.contains(k.value())).toList();
            if (!notSession.isEmpty()) {
                put(changes, new TraceRuleChange(Type.REMOVE_OVERWRITE_KEYS, system, c.annotation(), c.container(), null,
                        values(notSession), null, evidence(c.evidence(), List.of(), notSession)));
            }
            if (!Objects.equals(existing.requiredFirstParam(), c.requiredFirstParam())) {
                put(changes, new TraceRuleChange(Type.SET_FIRST_PARAM, system, c.annotation(), c.container(), c.requiredFirstParam(),
                        List.of(), null, List.of("지금 설정: " + (existing.requiredFirstParam() == null ? "조건 없음" : existing.requiredFirstParam()),
                        "코드: " + String.join(" / ", c.evidence()))));
            }
        }
        // 로그인 정보 이름·사용자 범위 키는 공통 + 이 시스템 항목 기준으로 이미 있는지 본다(다른 시스템 항목은 이 시스템에 적용되지 않는다).
        TraceRules effective = current.forSystem(system);
        for (Evidenced e : draft.loginTypeNames()) {
            if (effective.loginTypeNames().stream().noneMatch(e.value()::contains)) {
                put(changes, single(Type.ADD_LOGIN_TYPE, system, e));
            }
        }
        for (Evidenced e : draft.loginMethodPrefixes()) {
            if (effective.loginMethodPrefixes().stream().noneMatch(e.value()::startsWith)) {
                put(changes, single(Type.ADD_LOGIN_PREFIX, system, e));
            }
        }
        for (Evidenced e : draft.scopeKeys()) {
            if (!effective.userScopeKeys().contains(e.value())) {
                put(changes, single(Type.ADD_SCOPE_KEY, system, e));
            }
        }
        List<TraceRules.FrameworkFact> recorded = current.frameworks().getOrDefault(system, List.of());
        if (!draft.framework().isEmpty() && !draft.framework().equals(recorded)) {
            put(changes, new TraceRuleChange(Type.SET_FRAMEWORK, system, null, null, null, List.of(), draft.framework(),
                    draft.framework().stream().map(f -> f.kind() + ": " + f.value() + " ← " + f.evidence()).toList()));
        }
        return new Plan(new ArrayList<>(changes.values()), notes);
    }

    /** 같은 변경이 둘이면(어노테이션 AOP와 XML AOP가 같은 장치를 가리킬 때 등) 하나만. */
    private static void put(Map<String, TraceRuleChange> changes, TraceRuleChange change) {
        changes.putIfAbsent(change.key(), change);
    }

    private static TraceRuleChange single(Type type, String system, Evidenced e) {
        return new TraceRuleChange(type, system, null, null, null, List.of(e.value()), null, List.of(e.value() + " ← " + e.evidence()));
    }

    private static SessionOverwrite find(TraceRules rules, OverwriteCandidate c) {
        for (SessionOverwrite o : rules.sessionOverwrites()) {
            if (o.annotation().equals(c.annotation()) && Objects.equals(o.container(), c.container())) return o;
        }
        return null;
    }

    private static List<String> values(List<Evidenced> items) {
        return items.stream().map(Evidenced::value).toList();
    }

    private static List<Evidenced> only(List<Evidenced> items, List<String> keep) {
        Set<String> wanted = Set.copyOf(keep);
        return items.stream().filter(i -> wanted.contains(i.value())).toList();
    }

    private static List<String> evidence(List<String> advice, List<Evidenced> sessionKeys, List<Evidenced> nonSessionKeys) {
        List<String> lines = new ArrayList<>(advice);
        sessionKeys.forEach(k -> lines.add(k.value() + " ← " + k.evidence()));
        nonSessionKeys.forEach(k -> lines.add(k.value() + " (세션 값 아님) ← " + k.evidence()));
        return lines;
    }
}
