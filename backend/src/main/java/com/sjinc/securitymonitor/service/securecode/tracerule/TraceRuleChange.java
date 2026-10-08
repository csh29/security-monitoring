package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.FrameworkFact;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.SessionOverwrite;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * trace-rules.yml에 할 변경 하나(TraceRuleChangePlanner가 초안과 지금 설정을 비교해 만든다). 점검 중 바로 반영하거나,
 * 확인 대기로 DB(TraceRuleProposal)에 JSON으로 저장했다가 사람이 반영할 때 그대로 다시 적용한다.
 *
 * <p>모든 변경은 두 번 적용해도 결과가 같다(이미 있는 키를 더하거나 없는 키를 빼면 그대로) — 파일 쓰기와 DB 저장 사이에서 실패해
 * 같은 변경을 다시 반영해도 규칙이 꼬이지 않게.
 *
 * @param type               변경 종류
 * @param system             초안을 만든 시스템(앱의 시스템명). 새 세션 덮어쓰기 항목의 이름·프레임워크 구조의 키
 * @param annotation         세션 덮어쓰기 항목의 어노테이션(세션 덮어쓰기 변경만)
 * @param container          세션 덮어쓰기 항목의 덮어쓰는 위치(null이면 요청 맵 자체)
 * @param requiredFirstParam 첫 파라미터 조건(ADD_OVERWRITE·SET_FIRST_PARAM만, null이면 조건 없음)
 * @param values             더하거나 뺄 키·이름
 * @param facts              프레임워크 구조(SET_FRAMEWORK만)
 * @param evidence           근거(파일:줄 코드) — 사람이 반영할지 판단하고, 파일에 주석으로 남긴다
 */
public record TraceRuleChange(Type type, String system, String annotation, String container, String requiredFirstParam,
                              List<String> values, List<FrameworkFact> facts, List<String> evidence) {

    public enum Type {
        /** 새 세션 덮어쓰기 장치 — 그 키를 안전(세션 값)으로 본다. 판정이 느슨해진다 */
        ADD_OVERWRITE("세션 덮어쓰기 추가", false),
        /** 기존 장치가 세션 값으로 넣는 키 추가 — 판정이 느슨해진다 */
        ADD_OVERWRITE_KEYS("세션 덮어쓰기 키 추가", false),
        /** 기존 장치의 키 중 코드에서 세션 값이 아닌 값을 넣는 것으로 확인된 키 빼기 — 판정이 엄격해진다 */
        REMOVE_OVERWRITE_KEYS("세션 덮어쓰기 키 제외", true),
        /** 첫 파라미터 조건 바꾸기 — 방향이 경우마다 달라 사람이 본다 */
        SET_FIRST_PARAM("첫 파라미터 조건 변경", false),
        /** 로그인 정보 타입 이름 추가 — 그 객체의 값을 안전으로 본다. 판정이 느슨해진다 */
        ADD_LOGIN_TYPE("로그인 정보 타입 추가", false),
        /** 로그인 getter 접두어 추가 — 판정이 느슨해진다 */
        ADD_LOGIN_PREFIX("로그인 getter 접두어 추가", false),
        /** 사용자 범위 키 추가 — 판정 대상이 늘어 탐지가 많아질 수 있어 사람이 본다 */
        ADD_SCOPE_KEY("사용자 범위 키 추가", false),
        /** 프레임워크 구조 기록 — 판정에 쓰지 않는다 */
        SET_FRAMEWORK("프레임워크 구조 기록", true);

        private final String label;
        private final boolean automatic;

        Type(String label, boolean automatic) {
            this.label = label;
            this.automatic = automatic;
        }

        public String label() {
            return label;
        }

        /**
         * 점검 중 바로 반영하는가. 판정을 엄격하게 하거나(놓치는 쪽이 아니다) 판정에 쓰지 않는 변경만이다. 판정을 느슨하게 하는 변경을 잘못
         * 반영하면 진짜 취약점이 조용히 LOW로 묻히므로(regPgmId 사례) 사람이 근거를 보고 반영한다.
         */
        public boolean automatic() {
            return automatic;
        }
    }

    public TraceRuleChange {
        values = values == null ? List.of() : List.copyOf(values);
        facts = facts == null ? List.of() : List.copyOf(facts);
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
    }

    /**
     * 같은 변경인지 가르는 키 — 점검마다 같은 초안이 나오면 같은 확인 대기 한 건으로 묶고, 사람이 무시한 변경은 다시 묻지 않는다.
     * 근거(줄 번호)는 넣지 않는다 — 코드 위에 줄이 늘어도 같은 변경이다. 프레임워크 구조는 시스템별 하나다.
     */
    public String key() {
        return switch (type) {
            case SET_FRAMEWORK -> type + "|" + system;
            case ADD_LOGIN_TYPE, ADD_LOGIN_PREFIX, ADD_SCOPE_KEY -> type + "|" + String.join(",", values);
            case SET_FIRST_PARAM -> type + "|" + annotation + "|" + container + "|" + requiredFirstParam;
            default -> type + "|" + annotation + "|" + container + "|" + String.join(",", values.stream().sorted().toList());
        };
    }

    /** 화면·알림에 보일 한 줄. */
    public String summary() {
        String target = "@" + annotation + (container == null ? "" : " → " + container);
        return switch (type) {
            case ADD_OVERWRITE -> target + " 키 " + values
                    + (requiredFirstParam == null ? "" : " (첫 파라미터 " + requiredFirstParam + "일 때)");
            case ADD_OVERWRITE_KEYS -> target + " 키 추가 " + values;
            case REMOVE_OVERWRITE_KEYS -> target + " 키 제외 " + values + " — 세션 값이 아님";
            case SET_FIRST_PARAM -> target + " 첫 파라미터 조건 → " + (requiredFirstParam == null ? "없음" : requiredFirstParam);
            case ADD_LOGIN_TYPE, ADD_LOGIN_PREFIX, ADD_SCOPE_KEY -> String.join(", ", values);
            case SET_FRAMEWORK -> system + " 구조 " + facts.size() + "항목";
        };
    }

    /** 반영하면 판정이 어떻게 달라지는지 — 사람이 반영 여부를 정하는 기준. */
    public String effect() {
        return switch (type) {
            case ADD_OVERWRITE, ADD_OVERWRITE_KEYS -> "이 장치가 붙은 요청에서 위 키를 세션 값(안전)으로 판정합니다. 세션 값이 아닌 키가 섞이면 위험을 놓칩니다.";
            case REMOVE_OVERWRITE_KEYS -> "위 키를 클라이언트 값으로 판정합니다(더 엄격). 코드가 세션 값이 아닌 값을 넣는 것을 확인해 자동 반영했습니다.";
            case SET_FIRST_PARAM -> "이 장치를 적용할 요청 매핑의 조건이 바뀝니다. 조건이 없어지면 더 많은 요청을 안전으로 판정합니다.";
            case ADD_LOGIN_TYPE -> "이 이름이 들어간 타입의 객체에서 꺼낸 값을 로그인 정보(안전)로 판정합니다.";
            case ADD_LOGIN_PREFIX -> "이 이름으로 시작하는 메서드의 반환값을 로그인 정보(안전)로 판정합니다.";
            case ADD_SCOPE_KEY -> "이 키가 SQL 조건에 쓰인 곳마다 사용자 범위(인가) 판정을 합니다. 탐지가 늘어날 수 있습니다.";
            case SET_FRAMEWORK -> "기록만 합니다(판정에 쓰지 않음).";
        };
    }

    /** 규칙에 이 변경을 적용한 결과. 이미 반영된 변경이면 그대로다. */
    public TraceRules applyTo(TraceRules rules) {
        return switch (type) {
            case ADD_OVERWRITE -> {
                List<SessionOverwrite> overwrites = new ArrayList<>(rules.sessionOverwrites());
                int at = indexOf(overwrites);
                if (at >= 0) {
                    // 그사이 누가 같은 장치를 손으로 넣었으면 키만 합친다(항목을 둘로 만들지 않는다).
                    overwrites.set(at, withKeys(overwrites.get(at), union(overwrites.get(at).keys(), values)));
                } else {
                    overwrites.add(new SessionOverwrite(overwriteName(), annotation, container, requiredFirstParam,
                            new LinkedHashSet<>(values)));
                }
                yield with(rules, overwrites);
            }
            case ADD_OVERWRITE_KEYS, REMOVE_OVERWRITE_KEYS -> {
                List<SessionOverwrite> overwrites = new ArrayList<>(rules.sessionOverwrites());
                int at = indexOf(overwrites);
                if (at < 0) yield rules;
                SessionOverwrite o = overwrites.get(at);
                Set<String> keys = type == Type.ADD_OVERWRITE_KEYS ? union(o.keys(), values) : minus(o.keys(), values);
                overwrites.set(at, withKeys(o, keys));
                yield with(rules, overwrites);
            }
            case SET_FIRST_PARAM -> {
                List<SessionOverwrite> overwrites = new ArrayList<>(rules.sessionOverwrites());
                int at = indexOf(overwrites);
                if (at < 0) yield rules;
                SessionOverwrite o = overwrites.get(at);
                overwrites.set(at, new SessionOverwrite(o.name(), o.annotation(), o.container(), requiredFirstParam, o.keys()));
                yield with(rules, overwrites);
            }
            case ADD_LOGIN_TYPE -> new TraceRules(rules.sessionOverwrites(), rules.loginMethodPrefixes(),
                    union(rules.loginTypeNames(), values), rules.userScopeKeys(), rules.frameworks());
            case ADD_LOGIN_PREFIX -> new TraceRules(rules.sessionOverwrites(), union(rules.loginMethodPrefixes(), values),
                    rules.loginTypeNames(), rules.userScopeKeys(), rules.frameworks());
            case ADD_SCOPE_KEY -> new TraceRules(rules.sessionOverwrites(), rules.loginMethodPrefixes(),
                    rules.loginTypeNames(), union(rules.userScopeKeys(), values), rules.frameworks());
            case SET_FRAMEWORK -> rules.withFramework(system, facts);
        };
    }

    /** 새 세션 덮어쓰기 항목의 이름 — 어느 시스템 점검에서 나온 장치인지 알 수 있게. */
    String overwriteName() {
        return system + " @" + annotation;
    }

    /** 같은 장치(어노테이션·위치)인 항목의 위치. 없으면 -1. */
    int indexOf(List<SessionOverwrite> overwrites) {
        for (int i = 0; i < overwrites.size(); i++) {
            SessionOverwrite o = overwrites.get(i);
            if (o.annotation().equals(annotation) && Objects.equals(o.container(), container)) return i;
        }
        return -1;
    }

    private static SessionOverwrite withKeys(SessionOverwrite o, Set<String> keys) {
        return new SessionOverwrite(o.name(), o.annotation(), o.container(), o.requiredFirstParam(), keys);
    }

    private static TraceRules with(TraceRules rules, List<SessionOverwrite> overwrites) {
        return new TraceRules(overwrites, rules.loginMethodPrefixes(), rules.loginTypeNames(), rules.userScopeKeys(),
                rules.frameworks());
    }

    private static Set<String> union(Set<String> base, List<String> add) {
        Set<String> result = new LinkedHashSet<>(base);
        result.addAll(add);
        return result;
    }

    private static Set<String> minus(Set<String> base, List<String> remove) {
        Set<String> result = new LinkedHashSet<>(base);
        remove.forEach(result::remove);
        return result;
    }
}
