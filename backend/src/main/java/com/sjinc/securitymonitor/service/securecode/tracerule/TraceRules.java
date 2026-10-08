package com.sjinc.securitymonitor.service.securecode.tracerule;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * MyBatis ${} 연계 추적(MybatisDollarTracer)이 시스템마다 다른 프레임워크 규칙을 알기 위한 설정 — securecode/trace-rules.yml.
 *
 * <p>판정 로직에 특정 시스템의 어노테이션·키 이름을 박아 두지 않고 여기로 뺀다. 규칙은 대상 코드에 그 어노테이션·메서드가
 * 있을 때만 적용되므로, 여러 시스템의 규칙을 한 파일에 같이 둬도 서로 간섭하지 않는다. 새 시스템을 점검 대상에 넣을 때
 * 그 시스템이 세션 값을 어떻게 넣는지 보고 항목을 추가하면 된다.
 *
 * @param sessionOverwrites 요청 매핑에 붙으면 요청 맵의 키를 세션 값으로 덮어쓰는 장치(AOP 등)
 * @param loginMethodPrefixes 이 이름으로 시작하는 메서드의 반환값은 로그인 정보(서버 값)로 본다(예: getLogin)
 * @param loginTypeNames 이 문자열이 타입 이름에 들어간 객체에서 꺼낸 값은 로그인 정보로 본다(예: LoginUser)
 * @param userScopeKeys 매퍼 SQL에서 이 키(#{key}·${key})가 쓰이면 사용자 범위 조건(회사·브랜드·사용자로 데이터를 가르는 값)으로 본다.
 *                      그 값을 클라이언트가 정할 수 있으면 다른 사용자의 데이터에 접근할 수 있다(UserScopeFindings). 비면 이 판정을 하지 않는다
 * @param frameworks 시스템 이름 → 점검 때 설정 파일·소스에서 읽은 프레임워크 구조(FrameworkProfiler). <b>판정에는 쓰지 않는다</b> —
 *                   사람이 추적 규칙 초안을 판단할 때 "이 시스템은 어떤 구조인가"를 보는 기록이다
 */
public record TraceRules(List<SessionOverwrite> sessionOverwrites, Set<String> loginMethodPrefixes,
                         Set<String> loginTypeNames, Set<String> userScopeKeys,
                         Map<String, List<FrameworkFact>> frameworks) {

    /** 프레임워크 구조 기록 없이(판정에 필요한 규칙만). */
    public TraceRules(List<SessionOverwrite> sessionOverwrites, Set<String> loginMethodPrefixes,
                      Set<String> loginTypeNames, Set<String> userScopeKeys) {
        this(sessionOverwrites, loginMethodPrefixes, loginTypeNames, userScopeKeys, Map.of());
    }

    /** 사용자 범위 키 없이(사용자 범위 판정을 하지 않는 규칙). */
    public TraceRules(List<SessionOverwrite> sessionOverwrites, Set<String> loginMethodPrefixes, Set<String> loginTypeNames) {
        this(sessionOverwrites, loginMethodPrefixes, loginTypeNames, Set.of());
    }

    /**
     * 프레임워크 구조 한 줄.
     *
     * @param kind     구분(웹·영속성·AOP·인터셉터·필터·세션·설정 파일 — FrameworkProfiler.Kind의 이름)
     * @param value    무엇인가(예: "Spring Boot 2.7.18", "MyBatis")
     * @param evidence 어디서 읽었나(파일:줄 또는 파일과 그 안의 이름). 값(비밀번호 등)은 넣지 않는다
     */
    public record FrameworkFact(String kind, String value, String evidence) {
    }

    /**
     * @param name               사람이 알아볼 이름(근거 표시용)
     * @param annotation         요청 매핑 메서드에 붙는 어노테이션 이름(@ 없이)
     * @param container          덮어쓰는 위치 — 요청 맵 안의 이 키가 가리키는 맵. null이면 요청 맵 자체
     * @param requiredFirstParam 이 타입이 첫 파라미터일 때만 동작(AOP 포인트컷이 args(request, ..)인 경우). null이면 조건 없음
     * @param keys               덮어쓰는 키
     */
    public record SessionOverwrite(String name, String annotation, String container, String requiredFirstParam,
                                   Set<String> keys) {
    }

    public static TraceRules empty() {
        return new TraceRules(List.of(), Set.of(), Set.of());
    }

    /** 파일이 없으면 빈 규칙(세션 덮어쓰기를 모르면 해당 값을 클라이언트 값으로 본다 — 안전한 쪽). */
    public static TraceRules load(Path file) throws IOException {
        if (!Files.isRegularFile(file)) {
            return empty();
        }
        return parse(Files.readString(file, StandardCharsets.UTF_8));
    }

    /** 파일 내용을 읽는다. 서버가 파일을 고친 뒤 고친 내용이 의도한 규칙과 같은지 확인할 때도 쓴다(TraceRulesFileEditor). */
    public static TraceRules parse(String content) {
        // SafeConstructor: 설정 파일의 YAML 태그로 임의 클래스를 만들지 못하게 한다.
        Object root = new Yaml(new SafeConstructor(new LoaderOptions())).load(content);
        if (!(root instanceof Map<?, ?> map)) {
            return empty();
        }
        List<SessionOverwrite> overwrites = new ArrayList<>();
        for (Object item : list(map.get("sessionOverwrites"))) {
            if (!(item instanceof Map<?, ?> rule)) continue;
            String annotation = string(rule.get("annotation"));
            if (annotation == null) {
                throw new IllegalArgumentException("trace-rules.yml: sessionOverwrites 항목에 annotation이 없습니다: " + rule);
            }
            overwrites.add(new SessionOverwrite(
                    string(rule.get("name")) != null ? string(rule.get("name")) : "@" + annotation,
                    annotation.replaceFirst("^@", ""),
                    string(rule.get("container")),
                    string(rule.get("requiredFirstParam")),
                    strings(rule.get("keys"))));
        }
        return new TraceRules(overwrites, strings(map.get("loginMethodPrefixes")), strings(map.get("loginTypeNames")),
                strings(map.get("userScopeKeys")), frameworks(map.get("frameworks")));
    }

    /** 이 시스템의 프레임워크 구조만 바꾼 규칙. facts가 비면 그 시스템 기록을 지운다. */
    public TraceRules withFramework(String system, List<FrameworkFact> facts) {
        Map<String, List<FrameworkFact>> copy = new TreeMap<>(frameworks);
        if (facts.isEmpty()) copy.remove(system);
        else copy.put(system, List.copyOf(facts));
        return new TraceRules(sessionOverwrites, loginMethodPrefixes, loginTypeNames, userScopeKeys, copy);
    }

    private static Map<String, List<FrameworkFact>> frameworks(Object value) {
        Map<String, List<FrameworkFact>> result = new TreeMap<>();
        if (!(value instanceof Map<?, ?> systems)) return result;
        systems.forEach((system, items) -> {
            List<FrameworkFact> facts = new ArrayList<>();
            for (Object item : list(items)) {
                if (!(item instanceof Map<?, ?> fact)) continue;
                facts.add(new FrameworkFact(string(fact.get("kind")), string(fact.get("value")), string(fact.get("evidence"))));
            }
            if (system != null && !facts.isEmpty()) result.put(system.toString(), facts);
        });
        return result;
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> list ? list : List.of();
    }

    private static Set<String> strings(Object value) {
        Set<String> result = new LinkedHashSet<>();
        for (Object item : list(value)) {
            if (item != null && !item.toString().isBlank()) result.add(item.toString().trim());
        }
        return result;
    }

    private static String string(Object value) {
        return value == null || value.toString().isBlank() ? null : value.toString().trim();
    }
}
