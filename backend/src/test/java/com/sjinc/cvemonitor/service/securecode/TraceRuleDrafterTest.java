package com.sjinc.cvemonitor.service.securecode;

import com.sjinc.cvemonitor.service.securecode.TraceRuleDraftPreview.Status;
import com.sjinc.cvemonitor.service.securecode.TraceRuleDrafter.Draft;
import com.sjinc.cvemonitor.service.securecode.TraceRuleDrafter.Evidenced;
import com.sjinc.cvemonitor.service.securecode.TraceRuleDrafter.OverwriteCandidate;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TraceRuleDrafterTest {

    /** sjinc 프레임워크와 같은 모양: aspect → util → private, 요청 인자의 paramData에 세션 값을 넣고 하나는 세션 값이 아님. */
    private static final String ASPECT = """
            package f;
            import java.util.*;
            @Aspect
            class UserAspect {
                @Before("@annotation(f.AddUser) && args(request, ..)")
                public void before(JoinPoint joinPoint, HttpServletRequest request) {
                    Object[] args = joinPoint.getArgs();
                    for (Object arg : args) {
                        if (arg instanceof HashMap) Util.fill((HashMap) arg, request);
                    }
                }
            }
            """;
    private static final String UTIL = """
            package f;
            import java.util.*;
            class Util {
                static void fill(HashMap map, HttpServletRequest request) {
                    UserVo user = (UserVo) request.getSession().getAttribute("USER");
                    Map paramData = (Map) map.get("paramData");
                    put(map, paramData, user);
                }
                private static void put(HashMap top, Map target, UserVo user) {
                    target.put("loginCompCd", user.getLoginCompCd());
                    target.put("loginUserId", user.getLoginUserId());
                    target.put("pgmId", top.get("statement").toString().substring(0, 6));
                }
            }
            """;
    private static final String USER_VO = """
            package f;
            class UserVo {
                private String loginCompCd;
                private String loginUserId;
                public String getLoginCompCd() { return loginCompCd; }
                public String getLoginUserId() { return loginUserId; }
            }
            """;

    @Test
    void AOP_포인트컷과_호출을_따라가_세션_덮어쓰기_후보를_찾는다() {
        Draft draft = TraceRuleDrafter.draft(sources(ASPECT, UTIL, USER_VO));

        assertThat(draft.overwrites()).hasSize(1);
        OverwriteCandidate c = draft.overwrites().get(0);
        assertThat(c.annotation()).isEqualTo("AddUser");
        assertThat(c.container()).isEqualTo("paramData");
        assertThat(c.requiredFirstParam()).isEqualTo("HttpServletRequest");
        assertThat(c.keys()).extracting(Evidenced::value).containsExactly("loginCompCd", "loginUserId");
        // 세션 값이 아닌 키는 따로 — 등록하면 클라이언트가 바꿀 수 있는 값을 안전하다고 판정하게 된다.
        assertThat(c.nonSessionKeys()).extracting(Evidenced::value).containsExactly("pgmId");
        assertThat(draft.loginTypeNames()).extracting(Evidenced::value).containsExactly("UserVo");
        assertThat(draft.loginMethodPrefixes()).extracting(Evidenced::value).containsExactly("getLogin");
    }

    @Test
    void 이름_붙은_포인트컷과_요청_맵_자체_덮어쓰기() {
        String aspect = """
                package f;
                import java.util.*;
                @Aspect
                class A {
                    @Pointcut("@annotation(Inject)")
                    void inject() {}
                    @Around("inject()")
                    public Object around(ProceedingJoinPoint pjp) {
                        for (Object arg : pjp.getArgs()) {
                            Map m = (Map) arg;
                            UserVo u = (UserVo) RequestContextHolder.currentRequestAttributes();
                            m.put("loginUserId", ((HttpSession) session).getAttribute("ID"));
                        }
                        return null;
                    }
                }
                """;
        Draft draft = TraceRuleDrafter.draft(sources(aspect, USER_VO));

        OverwriteCandidate c = draft.overwrites().get(0);
        assertThat(c.annotation()).isEqualTo("Inject");
        assertThat(c.container()).isNull();
        assertThat(c.requiredFirstParam()).isNull();
    }

    @Test
    void AOP가_없으면_안내를_남기고_XML_AOP는_직접_확인하라고_한다() {
        Map<String, String> src = sources(USER_VO);
        src.put("src/main/resources/aop.xml", "<beans><aop:config/></beans>");

        Draft draft = TraceRuleDrafter.draft(src);

        assertThat(draft.overwrites()).isEmpty();
        assertThat(draft.notes()).anyMatch(n -> n.contains("<aop:config>")).anyMatch(n -> n.contains("찾지 못했습니다"));
    }

    @Test
    void 초안_YAML은_세션_값_키만_넣고_근거를_주석으로_단다() throws Exception {
        String yaml = TraceRuleDrafter.toYaml(TraceRuleDrafter.draft(sources(ASPECT, UTIL, USER_VO)), "TEST");

        assertThat(yaml).contains("keys: [loginCompCd, loginUserId]")
                .contains("# 세션 값이 아니라 넣지 않음: pgmId")
                .contains("container: paramData");
        // 그대로 붙여 넣으면 TraceRules가 읽을 수 있어야 한다.
        java.nio.file.Path file = java.nio.file.Files.createTempFile("trace-rules", ".yml");
        try {
            java.nio.file.Files.writeString(file, yaml);
            TraceRules rules = TraceRules.load(file);
            assertThat(rules.sessionOverwrites()).singleElement()
                    .satisfies(o -> assertThat(o.keys()).containsExactly("loginCompCd", "loginUserId"));
            assertThat(rules.loginTypeNames()).containsExactly("UserVo");
        } finally {
            java.nio.file.Files.deleteIfExists(file);
        }
    }

    @Test
    void 지금_설정과_비교한다() {
        Draft draft = TraceRuleDrafter.draft(sources(ASPECT, UTIL, USER_VO));
        TraceRules same = new TraceRules(List.of(new TraceRules.SessionOverwrite("x", "AddUser", "paramData",
                "HttpServletRequest", Set.of("loginCompCd", "loginUserId"))), Set.of("getLogin"), Set.of("UserVo"));
        TraceRules different = new TraceRules(List.of(new TraceRules.SessionOverwrite("x", "AddUser", "paramData",
                "HttpServletRequest", Set.of("loginCompCd", "pgmId"))), Set.of(), Set.of());

        assertThat(TraceRuleDraftPreview.compare(same, draft)).extracting(TraceRuleDraftPreview.Item::status)
                .containsOnly(Status.SAME);
        assertThat(TraceRuleDraftPreview.compare(TraceRules.empty(), draft)).extracting(TraceRuleDraftPreview.Item::status)
                .containsOnly(Status.NEW);
        TraceRuleDraftPreview.Item item = TraceRuleDraftPreview.compare(different, draft).get(0);
        assertThat(item.status()).isEqualTo(Status.DIFFERENT);
        assertThat(item.detail()).contains("추가 [loginUserId]").contains("빠짐 [pgmId]");
    }

    @Test
    void 반영하면_바뀌는_판정을_미리_계산한다() {
        Map<String, String> src = sources(ASPECT, UTIL, USER_VO, """
                package f;
                import java.util.*;
                @RestController
                class C {
                    private SqlSessionTemplate sql;
                    @AddUser
                    @PostMapping("/x") public Object x(HttpServletRequest request, @RequestBody HashMap<String, Object> param) {
                        Map paramData = (Map) param.get("paramData");
                        return sql.selectList("t.q", paramData);
                    }
                }
                """);
        src.put("src/main/resources/mapper/t.xml", """
                <mapper namespace="t"><select id="q">SELECT * FROM T_${loginCompCd}</select></mapper>
                """);
        Draft draft = TraceRuleDrafter.draft(src);
        TraceRules merged = TraceRuleDraftPreview.merge(TraceRules.empty(), draft, "TEST");

        List<TraceRuleDraftPreview.Change> changes = TraceRuleDraftPreview.changes(
                MybatisDollarTracer.trace(src, TraceRules.empty()), MybatisDollarTracer.trace(src, merged));

        assertThat(changes).singleElement().satisfies(c -> {
            assertThat(c.before()).isEqualTo(DollarVerdict.Safety.CLIENT);
            assertThat(c.after()).isEqualTo(DollarVerdict.Safety.SESSION_OVERWRITE);
        });
    }

    @Test
    void 점검_완료_알림_문구는_설정과_다를_때만_만든다() {
        Draft draft = TraceRuleDrafter.draft(sources(ASPECT, UTIL, USER_VO));
        TraceRules same = new TraceRules(List.of(new TraceRules.SessionOverwrite("x", "AddUser", "paramData",
                "HttpServletRequest", Set.of("loginCompCd", "loginUserId"))), Set.of("getLogin"), Set.of("UserVo"));
        TraceRules wrongKey = new TraceRules(List.of(new TraceRules.SessionOverwrite("x", "AddUser", "paramData",
                "HttpServletRequest", Set.of("loginCompCd", "pgmId"))), Set.of("getLogin"), Set.of("UserVo"));

        assertThat(TraceRuleDraftPreview.note(TraceRuleDraftPreview.compare(same, draft), 0)).isNull();
        assertThat(TraceRuleDraftPreview.note(TraceRuleDraftPreview.compare(wrongKey, draft), 3))
                .contains("다른 항목 1개", "@AddUser → paramData", "빠짐 [pgmId]", "판정 3건", "서버 로그");
    }

    @Test
    void 카멜_단어_경계_공통_접두어() {
        assertThat(TraceRuleDrafter.commonCamelPrefix(Set.of("getLoginCompCd", "getLoginUserId"))).isEqualTo("getLogin");
        assertThat(TraceRuleDrafter.commonCamelPrefix(Set.of("getLoginId", "getLogoutAt"))).isEqualTo("get");
        assertThat(TraceRuleDrafter.commonCamelPrefix(Set.of())).isNull();
    }

    private static Map<String, String> sources(String... javaSources) {
        Map<String, String> sources = new LinkedHashMap<>();
        for (int i = 0; i < javaSources.length; i++) sources.put("src/main/java/f/S" + i + ".java", javaSources[i]);
        return sources;
    }
}
