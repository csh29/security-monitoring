package com.sjinc.securitymonitor.service.securecode.trace;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.DollarVerdict;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.SecureCodeSnippetBuilder;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** 사용자 범위 키(#{})의 값 출처 판정(MybatisDollarTracer.scopeVerdicts)과 그 판정으로 만든 탐지(UserScopeFindings). */
class UserScopeTraceTest {

    /**
     * 가상의 다른 시스템 규칙 — 판정 로직에는 시스템 이름이 없고, 이 설정만 바꾸면 그 시스템을 판정한다.
     * @CurrentUser가 요청 맵 자체의 companyId를 세션 값으로 덮어쓴다.
     */
    private static final TraceRules OTHER_SYSTEM = new TraceRules(
            List.of(new TraceRules.SessionOverwrite("other @CurrentUser", "CurrentUser", null, null, Set.of("companyId"))),
            Set.of(), Set.of(), Set.of("companyId", "userId"));

    private static final String MAPPER_PATH = "src/main/resources/mapper/order.xml";
    private static final String MAPPER = """
            <?xml version="1.0" encoding="UTF-8"?>
            <mapper namespace="order">
                <select id="list">
                    SELECT * FROM orders
                    WHERE company_id = #{companyId, jdbcType=VARCHAR}
                      AND user_id = #{userId}
                      AND status = #{status}
                      AND tbl = ${companyId}
                </select>
            </mapper>
            """;

    private static final String SERVICE = """
            package p;
            import java.util.*;
            class S {
                private SqlSessionTemplate sql;
                public Object list(Map<String, Object> param) {
                    return sql.selectList("order.list", param);
                }
            }""";

    private static MybatisDollarTracer.Result trace(TraceRules rules, String controller, String... extra) {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put(MAPPER_PATH, MAPPER);
        sources.put("src/main/java/p/C.java", controller);
        sources.put("src/main/java/p/S.java", SERVICE);
        for (int i = 0; i < extra.length; i++) sources.put("src/main/java/p/X" + i + ".java", extra[i]);
        MybatisDollarTracer.Result result = MybatisDollarTracer.trace(sources, rules);
        assertThat(result.failedFiles()).isEmpty();
        return result;
    }

    private static Map<String, TraceSafety> byKey(MybatisDollarTracer.Result result) {
        Map<String, TraceSafety> map = new LinkedHashMap<>();
        result.scopeVerdicts().forEach(v -> map.put(v.key(), v.safety()));
        return map;
    }

    private static String controller(String annotation) {
        return """
                package p;
                import java.util.*;
                @RestController
                class C {
                    private final S s;
                    %s
                    @PostMapping("/orders") public Object list(@RequestBody Map<String, Object> param) {
                        return s.list(param);
                    }
                }""".formatted(annotation);
    }

    @Test
    void 클라이언트가_보낸_사용자_범위_키는_클라이언트_값이다() {
        MybatisDollarTracer.Result result = trace(OTHER_SYSTEM, controller(""));

        assertThat(byKey(result)).containsEntry("companyId", TraceSafety.CLIENT).containsEntry("userId", TraceSafety.CLIENT);
        // 사용자 범위 키가 아닌 #{status}는 보지 않는다
        assertThat(byKey(result)).doesNotContainKey("status");
        assertThat(result.scopeKeysUsed()).isTrue();
    }

    @Test
    void 설정된_장치가_세션_값으로_덮어쓰면_안전하다() {
        Map<String, TraceSafety> v = byKey(trace(OTHER_SYSTEM, controller("@CurrentUser")));

        assertThat(v).containsEntry("companyId", TraceSafety.SESSION_OVERWRITE);
        // 장치가 덮어쓰지 않는 키는 그대로 클라이언트 값
        assertThat(v).containsEntry("userId", TraceSafety.CLIENT);
    }

    @Test
    void 서비스가_로그인_정보로_넣어도_공통_실행_경로로_부르면_우회된다() {
        TraceRules rules = new TraceRules(List.of(), Set.of("getLogin"), Set.of(), Set.of("userId"));
        String controller = """
                package p;
                import java.util.*;
                @RestController
                class C {
                    private final S s;
                    private final Q q;
                    @PostMapping("/orders") public Object list(@RequestBody Map<String, Object> param, LoginInfo login) {
                        param.put("userId", login.getLoginUserId());
                        return s.list(param);
                    }
                    @PostMapping("/common/select") public Object common(@RequestBody Map<String, Object> param) {
                        return q.select((String) param.get("statement"), param);
                    }
                }""";
        String generic = """
                package p;
                import java.util.*;
                class Q {
                    private SqlSessionTemplate sql;
                    public Object select(String statement, Map<String, Object> param) {
                        return sql.selectList(statement, param);
                    }
                }""";

        assertThat(byKey(trace(rules, controller, generic))).containsEntry("userId", TraceSafety.BYPASSABLE);
    }

    @Test
    void 유틸_메서드가_만들어_돌려준_맵도_그_안의_put을_따라간다() {
        TraceRules rules = new TraceRules(List.of(), Set.of("getLogin"), Set.of(), Set.of("companyId", "userId"));
        String controller = """
                package p;
                import java.util.*;
                @RestController
                class C {
                    private final S s;
                    @PostMapping("/orders") public Object list(@RequestBody Map<String, Object> param, LoginInfo login) {
                        Map<String, Object> row = MapUtil.build(param, login);
                        return s.list(row);
                    }
                }""";
        String util = """
                package p;
                import java.util.*;
                class MapUtil {
                    static Map<String, Object> build(Map<String, Object> src, LoginInfo login) {
                        Map<String, Object> m = new HashMap<>();
                        m.put("companyId", login.getLoginCompanyId());
                        m.put("userId", src.get("userId"));
                        return m;
                    }
                }""";

        Map<String, TraceSafety> v = byKey(trace(rules, controller, util));

        assertThat(v).containsEntry("companyId", TraceSafety.SERVER_SET).containsEntry("userId", TraceSafety.CLIENT);
    }

    /** 매퍼 하나를 읽어 #{key} → 조건 자리인가(같은 키가 여러 번이면 순서대로). */
    private static List<String> clauses(String body) {
        MapperXmlIndex.MapperFile file = MapperXmlIndex.parse("m.xml",
                "<mapper namespace=\"m\">\n" + body + "\n</mapper>");
        List<String> result = new java.util.ArrayList<>();
        file.statements().forEach(s -> s.hashes().forEach(h -> result.add(h.key() + "=" + (h.condition() ? "조건" : "값"))));
        file.fragments().forEach(f -> f.hashes().forEach(h -> result.add(h.key() + "=" + (h.condition() ? "조건" : "값"))));
        return result;
    }

    @Test
    void 사용자_범위_키가_조건_자리인지_값_자리인지_가른다() {
        // INSERT 값은 등록자 기록, INSERT … SELECT의 WHERE는 조건
        assertThat(clauses("""
                <insert id="a">INSERT INTO t (comp_cd, reg_id) VALUES (#{companyId}, #{userId})</insert>
                <insert id="b">INSERT INTO t SELECT * FROM s WHERE comp_cd = #{companyId}</insert>
                """)).containsExactly("companyId=값", "userId=값", "companyId=조건");
        // UPDATE SET은 값, 그 뒤 WHERE는 조건. SET 안의 서브쿼리 WHERE도 조건
        assertThat(clauses("""
                <update id="u">UPDATE t SET upd_id = #{userId}, x = (SELECT y FROM z WHERE comp = #{companyId})
                  WHERE comp_cd = #{companyId} AND user_id = #{userId}</update>
                """)).containsExactly("userId=값", "companyId=조건", "companyId=조건", "userId=조건");
        // 동적 SQL 태그가 키워드보다 먼저다
        assertThat(clauses("""
                <update id="d">UPDATE t <set><if test="x != null">upd_id = #{userId},</if></set>
                  <where><if test="y != null">AND comp_cd = #{companyId}</if></where></update>
                <update id="t">UPDATE t <trim prefix="SET" suffixOverrides=",">upd_id = #{userId},</trim>
                  <trim prefix="WHERE" prefixOverrides="AND">AND comp_cd = #{companyId}</trim></update>
                """)).containsExactly("userId=값", "companyId=조건", "userId=값", "companyId=조건");
        // MERGE ON은 조건, MySQL ON DUPLICATE KEY UPDATE는 값. 주석 안의 키워드는 무시
        assertThat(clauses("""
                <insert id="m">MERGE INTO t USING dual ON (comp_cd = #{companyId})
                  WHEN MATCHED THEN UPDATE SET upd_id = #{userId}</insert>
                <insert id="k">INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE upd_id = #{userId}</insert>
                <insert id="c">INSERT INTO t (reg_id) /* where 조건 없음 */ VALUES (#{userId})</insert>
                """)).containsExactly("companyId=조건", "userId=값", "userId=값", "userId=값");
        // 키워드가 없는 조각은 조건(WHERE 뒤에 include되는 게 보통 — 모르면 놓치지 않는 쪽)
        assertThat(clauses("""
                <sql id="scope">AND comp_cd = #{companyId}</sql>
                """)).containsExactly("companyId=조건");
    }

    @Test
    void 값_자리의_사용자_범위_키는_인가_판정에서_빠진다() {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put(MAPPER_PATH, """
                <mapper namespace="order">
                    <insert id="list">INSERT INTO log (reg_id) VALUES (#{userId})</insert>
                </mapper>
                """);
        sources.put("src/main/java/p/C.java", controller(""));
        sources.put("src/main/java/p/S.java", SERVICE);

        MybatisDollarTracer.Result result = MybatisDollarTracer.trace(sources, OTHER_SYSTEM);

        // 클라이언트 값이지만 등록자 기록이라 인가 탐지가 아니다. 키 자체는 이 시스템에 있으니 "키를 찾지 못함" 알림은 뜨지 않는다.
        assertThat(result.scopeVerdicts()).isEmpty();
        assertThat(result.scopeKeysUsed()).isTrue();
    }

    @Test
    void 설정된_키가_매퍼에_없으면_판정이_없고_그_사실을_알린다() {
        TraceRules crmKeys = new TraceRules(List.of(), Set.of(), Set.of(), Set.of("loginCompCd"));

        MybatisDollarTracer.Result result = trace(crmKeys, controller(""));

        assertThat(result.scopeVerdicts()).isEmpty();
        assertThat(result.scopeKeysUsed()).isFalse();
    }

    @Test
    void 키_설정이_없으면_사용자_범위_판정을_하지_않는다() {
        MybatisDollarTracer.Result result = trace(TraceRules.empty(), controller(""));

        assertThat(result.scopeVerdicts()).isEmpty();
        // ${companyId}는 SQL 삽입 판정에 그대로 나온다(사용자 범위 판정과 겹치지 않게 #{}만 사용자 범위로 본다)
        assertThat(result.verdicts()).extracting(DollarVerdict::key).containsExactly("companyId");
    }

    @Test
    void 위험한_판정만_탐지가_되고_지문은_재점검에도_같다(@TempDir Path dir) throws Exception {
        Path mapper = dir.resolve(MAPPER_PATH);
        Files.createDirectories(mapper.getParent());
        Files.writeString(mapper, MAPPER, StandardCharsets.UTF_8);
        MybatisDollarTracer.Result result = trace(OTHER_SYSTEM, controller("@CurrentUser"));

        List<DetectedFinding> first = UserScopeFindings.build(result.scopeVerdicts(), new SecureCodeSnippetBuilder(dir));
        List<DetectedFinding> again = UserScopeFindings.build(result.scopeVerdicts(), new SecureCodeSnippetBuilder(dir));

        // companyId는 세션 덮어쓰기라 안전 → 탐지 없음, userId만 클라이언트 값 → HIGH
        assertThat(first).hasSize(1);
        DetectedFinding f = first.get(0);
        assertThat(f.ruleId()).isEqualTo(UserScopeFindings.RULE_ID);
        assertThat(f.severity()).isEqualTo("HIGH");
        assertThat(f.traceSafety()).isEqualTo("CLIENT");
        assertThat(f.startLine()).isEqualTo(6);
        assertThat(f.snippet()).contains("#{userId}");
        assertThat(f.message()).contains("#{userId}").doesNotContain("AddUserInfo");
        assertThat(f.traceEvidence()).contains("order.xml:6 #{userId}");
        assertThat(again.get(0).fingerprint()).isEqualTo(f.fingerprint());
    }

    @Test
    void 매퍼_색인은_샵_파라미터의_첫_이름을_키로_쓴다() {
        MapperXmlIndex.MapperFile file = MapperXmlIndex.parse("order.xml", MAPPER);

        assertThat(file.statements().get(0).hashes()).extracting(MapperXmlIndex.Dollar::key)
                .containsExactly("companyId", "userId", "status");
        assertThat(file.statements().get(0).dollars()).extracting(MapperXmlIndex.Dollar::key).containsExactly("companyId");
    }

    @Test
    void 설정_파일의_userScopeKeys를_읽는다(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("trace-rules.yml");
        Files.writeString(file, "userScopeKeys: [companyId, userId]\n");

        assertThat(TraceRules.load(file).userScopeKeys()).containsExactly("companyId", "userId");
    }

    @Test
    void 실제_trace_rules_파일이_읽힌다() throws Exception {
        TraceRules rules = TraceRules.load(Path.of("../securecode/trace-rules.yml"));

        assertThat(rules.userScopeKeys()).isNotEmpty();
    }
}
