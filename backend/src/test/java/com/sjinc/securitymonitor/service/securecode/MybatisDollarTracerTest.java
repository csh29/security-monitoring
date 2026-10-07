package com.sjinc.securitymonitor.service.securecode;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MybatisDollarTracerTest {

    /** securecode/trace-rules.yml의 sjinc 항목과 같은 규칙. 판정 로직에는 없고 설정으로만 들어간다. */
    private static final TraceRules SJINC_RULES = new TraceRules(
            List.of(new TraceRules.SessionOverwrite("sjinc @AddUserInfo", "AddUserInfo", "paramData", "HttpServletRequest",
                    Set.of("loginCompCd", "loginUserId", "loginBrndzCd"))),
            Set.of("getLogin"), Set.of("LoginUser"));

    private static final String MAPPER = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
            <mapper namespace="t">
                <select id="q">
                    SELECT * FROM ${tableNm}
                    WHERE a = ${col}
                    <!-- ${commented} -->
                    <if test="sortOrd == 'A' or sortOrd == 'B'">ORDER BY ${sortOrd}</if>
                    <bind name="fixed" value="'X'"/>
                    AND b = ${fixed}
                    AND c = ${loginBrndzCd}
                </select>
            </mapper>
            """;

    private static final String CONTROLLER_HEAD = """
            package p;
            import java.util.*;
            @RestController
            class C {
                private final S s;
            """;

    private static final String SERVICE_HEAD = """
            package p;
            import java.util.*;
            class S {
                private SqlSessionTemplate sql;
            """;

    @Test
    void 상수_삼항_모든분기_상수반환메서드는_서버가_세팅() {
        Map<String, DollarVerdict> v = run("""
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody Map<String, Object> param) {
                        return s.run(param, true);
                    }
                }""", """
                    public Object run(Map<String, Object> param, boolean desc) {
                        param.put("tableNm", table(desc));
                        if (desc) { param.put("col", "A"); } else { param.put("col", desc ? "B" : "C"); }
                        return sql.selectList("t.q", param);
                    }
                    private String table(boolean desc) {
                        String result = "";
                        if (desc) result = "T_A"; else result = "T_B";
                        return result;
                    }
                }""");

        assertThat(v.get("tableNm").safety()).isEqualTo(TraceSafety.SERVER_SET);
        assertThat(v.get("col").safety()).isEqualTo(TraceSafety.SERVER_SET);
        assertThat(v).doesNotContainKey("commented");
    }

    @Test
    void else없는_조건부_세팅은_클라이언트_값이_남는다() {
        Map<String, DollarVerdict> v = run("""
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody Map<String, Object> param) {
                        return s.run(param, true);
                    }
                }""", """
                    public Object run(Map<String, Object> param, boolean desc) {
                        if (desc) param.put("col", "A");
                        return sql.selectList("t.q", param);
                    }
                }""");

        assertThat(v.get("col").safety()).isEqualTo(TraceSafety.CLIENT);
        assertThat(v.get("col").evidence()).anyMatch(e -> e.contains("조건부"));
        // 서버가 세팅하지 않은 키는 클라이언트 값
        assertThat(v.get("tableNm").safety()).isEqualTo(TraceSafety.CLIENT);
    }

    @Test
    void XML의_상수비교_if와_bind는_호출과_무관하게_안전() {
        Map<String, DollarVerdict> v = run("""
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody Map<String, Object> param) {
                        return s.run(param);
                    }
                }""", """
                    public Object run(Map<String, Object> param) {
                        return sql.selectList("t.q", param);
                    }
                }""");

        assertThat(v.get("sortOrd").safety()).isEqualTo(TraceSafety.XML_FIXED);
        assertThat(v.get("fixed").safety()).isEqualTo(TraceSafety.XML_FIXED);
    }

    @Test
    void AddUserInfo는_paramData_안의_login키만_덮어쓴다() {
        Map<String, DollarVerdict> v = run("""
                    @AddUserInfo
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody BaseParam param) {
                        Map paramData = (Map) param.get("paramData");
                        return s.run(paramData);
                    }
                }""", """
                    public Object run(Map<String, Object> param) {
                        return sql.selectList("t.q", param);
                    }
                }""");

        assertThat(v.get("loginBrndzCd").safety()).isEqualTo(TraceSafety.SESSION_OVERWRITE);
        assertThat(v.get("col").safety()).isEqualTo(TraceSafety.CLIENT);
    }

    @Test
    void AddUserInfo라도_첫_파라미터가_request가_아니면_AOP가_돌지_않는다() {
        Map<String, DollarVerdict> v = run("""
                    @AddUserInfo
                    @PostMapping("/x") public Object x(@RequestBody BaseParam param) {
                        Map paramData = (Map) param.get("paramData");
                        return s.run(paramData);
                    }
                }""", """
                    public Object run(Map<String, Object> param) {
                        return sql.selectList("t.q", param);
                    }
                }""");

        assertThat(v.get("loginBrndzCd").safety()).isEqualTo(TraceSafety.CLIENT);
    }

    @Test
    void 클라이언트가_구문id를_정하는_공통경로가_있으면_서비스의_세팅은_우회된다() {
        Map<String, DollarVerdict> v = run("""
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody Map<String, Object> param) {
                        return s.run(param);
                    }
                    @AddUserInfo
                    @PostMapping("/common/selectList") public Object common(HttpServletRequest request, @RequestBody BaseParam param) {
                        Map paramData = (Map) param.get("paramData");
                        return s.select(param.getStatement(), paramData);
                    }
                }""", """
                    public Object run(Map<String, Object> param) {
                        param.put("col", "A");
                        param.put("loginBrndzCd", "B");
                        return select("t.q", param);
                    }
                    public Object select(String statement, Map param) {
                        return sql.selectList(statement, param);
                    }
                }""", """
                package p;
                import java.util.*;
                class BaseParam extends HashMap<String, Object> {
                    public String getStatement() { return (String) this.get("statement"); }
                }""");

        assertThat(v.get("col").safety()).isEqualTo(TraceSafety.BYPASSABLE);
        assertThat(v.get("col").evidence()).anyMatch(e -> e.contains("/common/selectList"));
        // 세션 덮어쓰기 키는 공통 경로로 와도 안전 — 공통 경로를 확인한 결과도 근거에 남고, 마지막 줄은 그대로 매퍼 위치·식이다
        assertThat(v.get("loginBrndzCd").safety()).isEqualTo(TraceSafety.SERVER_SET);
        List<String> evidence = v.get("loginBrndzCd").evidence();
        assertThat(evidence).anyMatch(e -> e.startsWith("공통 실행 경로로 이 구문을 직접 불러도 세션 값으로 덮어씀")
                && e.contains("/common/selectList"));
        assertThat(evidence.get(evidence.size() - 1)).startsWith("t.xml:").contains("${loginBrndzCd}");
    }

    @Test
    void List를_넘기는_공통경로는_키에_닿지_않아_판정에서_뺀다() {
        Map<String, DollarVerdict> v = run("""
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody BaseParam param) {
                        Map paramData = (Map) param.get("paramData");
                        List<Map> rows = (List<Map>) paramData.get("rows");
                        return s.insertAll(param.getStatement(), rows);
                    }
                    @PostMapping("/y") public Object y(HttpServletRequest request, @RequestBody Map<String, Object> param) {
                        param.put("col", "A");
                        return s.run(param);
                    }
                }""", """
                    public Object insertAll(String statement, List<Map> rows) {
                        return sql.insert(statement, rows);
                    }
                    public Object run(Map<String, Object> param) {
                        return sql.selectList("t.q", param);
                    }
                }""", """
                package p;
                import java.util.*;
                class BaseParam extends HashMap<String, Object> {
                    public String getStatement() { return (String) this.get("statement"); }
                }""");

        assertThat(v.get("col").safety()).isEqualTo(TraceSafety.SERVER_SET);
    }

    @Test
    void 다른_프레임워크의_세션_덮어쓰기는_설정만_추가하면_된다() {
        // 요청 맵 자체(container 없음)에 덮어쓰고, 첫 파라미터 조건이 없는 가상의 다른 시스템 규칙
        TraceRules other = new TraceRules(
                List.of(new TraceRules.SessionOverwrite("other @InjectUser", "InjectUser", null, null, Set.of("loginBrndzCd"))),
                Set.of(), Set.of());
        String controller = """
                    @InjectUser
                    @PostMapping("/x") public Object x(@RequestBody Map<String, Object> param) {
                        return s.run(param);
                    }
                }""";
        String service = """
                    public Object run(Map<String, Object> param) {
                        return sql.selectList("t.q", param);
                    }
                }""";

        assertThat(run(other, controller, service).get("loginBrndzCd").safety()).isEqualTo(TraceSafety.SESSION_OVERWRITE);
        // 규칙이 없으면 같은 코드도 클라이언트 값으로 본다(모르면 위험한 쪽)
        assertThat(run(TraceRules.empty(), controller, service).get("loginBrndzCd").safety()).isEqualTo(TraceSafety.CLIENT);
    }

    @Test
    void 설정_파일을_읽는다(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path file = dir.resolve("trace-rules.yml");
        java.nio.file.Files.writeString(file, """
                sessionOverwrites:
                  - name: a
                    annotation: "@AddUserInfo"
                    container: paramData
                    keys: [k1, k2]
                loginMethodPrefixes: [getLogin]
                """);

        TraceRules rules = TraceRules.load(file);

        assertThat(rules.sessionOverwrites()).containsExactly(
                new TraceRules.SessionOverwrite("a", "AddUserInfo", "paramData", null, Set.of("k1", "k2")));
        assertThat(rules.loginMethodPrefixes()).containsExactly("getLogin");
        assertThat(rules.loginTypeNames()).isEmpty();
        assertThat(TraceRules.load(dir.resolve("없음.yml"))).isEqualTo(TraceRules.empty());
    }

    /** ${key}별 판정. 마지막 인자들은 추가 소스 파일. */
    private static Map<String, DollarVerdict> run(String controllerBody, String serviceBody, String... extra) {
        return run(SJINC_RULES, controllerBody, serviceBody, extra);
    }

    private static Map<String, DollarVerdict> run(TraceRules rules, String controllerBody, String serviceBody, String... extra) {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/resources/mapper/t.xml", MAPPER);
        sources.put("src/main/java/p/C.java", CONTROLLER_HEAD + controllerBody);
        sources.put("src/main/java/p/S.java", SERVICE_HEAD + serviceBody);
        for (int i = 0; i < extra.length; i++) {
            sources.put("src/main/java/p/X" + i + ".java", extra[i]);
        }
        MybatisDollarTracer.Result result = MybatisDollarTracer.trace(sources, rules);
        assertThat(result.failedFiles()).isEmpty();
        Map<String, DollarVerdict> byKey = new LinkedHashMap<>();
        result.verdicts().forEach(v -> byKey.put(v.key(), v));
        return byKey;
    }

    @Test
    void 매퍼_XML_줄번호와_주석_제외() {
        MapperXmlIndex.MapperFile file = MapperXmlIndex.parse("t.xml", MAPPER);
        List<MapperXmlIndex.Dollar> dollars = file.statements().get(0).dollars();
        assertThat(dollars).extracting(MapperXmlIndex.Dollar::key)
                .containsExactly("tableNm", "col", "sortOrd", "fixed", "loginBrndzCd");
        assertThat(dollars.get(0).line()).isEqualTo(5);
        assertThat(MapperXmlIndex.parse("pom.xml", "<project><a>${x}</a></project>")).isNull();
    }
}
