package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.Draft;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.Evidenced;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.OverwriteCandidate;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.trace.MybatisDollarTracer;

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
    void AOP가_없으면_안내를_남긴다() {
        Draft draft = TraceRuleDrafter.draft(sources(USER_VO));

        assertThat(draft.overwrites()).isEmpty();
        assertThat(draft.notes()).anyMatch(n -> n.contains("찾지 못했습니다"));
    }

    /** 옛 Spring XML 시스템 — 애스펙트를 XML로 걸어도 어노테이션 AOP와 같은 후보가 나온다. */
    @Test
    void XML_AOP도_세션_덮어쓰기_후보를_찾는다() {
        String xmlAspect = """
                package f;
                import java.util.*;
                public class UserAspect {
                    public void before(JoinPoint joinPoint, HttpServletRequest request) {
                        for (Object arg : joinPoint.getArgs()) {
                            if (arg instanceof HashMap) Util.fill((HashMap) arg, request);
                        }
                    }
                }
                """;
        Map<String, String> src = sources(xmlAspect, UTIL, USER_VO);
        src.put("src/main/webapp/WEB-INF/aop-context.xml", """
                <beans>
                  <bean id="userAspect" class="f.UserAspect"/>
                  <aop:config>
                    <aop:pointcut id="userInfo" expression="@annotation(f.AddUser) and args(request, ..)"/>
                    <aop:aspect ref="userAspect">
                      <aop:before method="before" pointcut-ref="userInfo"/>
                    </aop:aspect>
                  </aop:config>
                </beans>
                """);

        Draft draft = TraceRuleDrafter.draft(src);

        assertThat(draft.overwrites()).singleElement().satisfies(c -> {
            assertThat(c.annotation()).isEqualTo("AddUser");
            assertThat(c.container()).isEqualTo("paramData");
            assertThat(c.requiredFirstParam()).isEqualTo("HttpServletRequest");
            assertThat(c.keys()).extracting(Evidenced::value).containsExactly("loginCompCd", "loginUserId");
            assertThat(c.evidence()).singleElement().asString().contains("aop-context.xml:6", "aop:before");
        });
        assertThat(draft.framework()).anyMatch(f -> f.value().equals("XML AOP(<aop:config>)"));
    }

    @Test
    void XML_AOP의_어드바이스_메서드가_소스에_없으면_안내한다() {
        Map<String, String> src = sources(USER_VO);
        src.put("src/main/resources/aop.xml", """
                <beans><aop:config><aop:aspect ref="libAspect"><aop:around method="run" pointcut="@annotation(X)"/></aop:aspect></aop:config></beans>
                """);

        Draft draft = TraceRuleDrafter.draft(src);

        assertThat(draft.overwrites()).isEmpty();
        assertThat(draft.notes()).anyMatch(n -> n.contains("LibAspect.run") && n.contains("찾지 못했습니다"));
    }

    @Test
    void 세션_값_키_중_매퍼_조건_자리에_쓰인_것만_사용자_범위_키_후보다() {
        Map<String, String> src = sources(ASPECT, UTIL, USER_VO);
        src.put("src/main/resources/mapper/t.xml", """
                <mapper namespace="t">
                  <select id="q">SELECT * FROM T WHERE COMP_CD = #{loginCompCd}</select>
                  <insert id="i">INSERT INTO T (REG_ID) VALUES (#{loginUserId})</insert>
                </mapper>
                """);

        Draft draft = TraceRuleDrafter.draft(src);

        // loginUserId는 INSERT 값 자리(등록자 기록)에만 쓰여 후보가 아니다.
        assertThat(draft.scopeKeys()).extracting(Evidenced::value).containsExactly("loginCompCd");
        assertThat(draft.scopeKeys().get(0).evidence()).isEqualTo("t.xml:2 #{loginCompCd}");
    }

    /** 공통 장치(AOP) 없이 서비스가 세션에서 꺼낸 로그인 정보를 직접 넣는 시스템. */
    @Test
    void 서비스가_로그인_정보로_넣는_키도_사용자_범위_키_후보다() {
        String service = """
                package f;
                import java.util.*;
                class OrderService {
                    List list(Map param, HttpSession session) {
                        UserVo user = (UserVo) session.getAttribute("USER");
                        param.put("compCd", user.getLoginCompCd());
                        param.put("regId", user.getLoginUserId());
                        param.put("sort", param.get("sort"));
                        return sql.selectList("o.list", param);
                    }
                    List byUtil(Map param) {
                        param.put("brandCd", SessionUtil.current().getLoginBrandCd());
                        return sql.selectList("o.brand", param);
                    }
                }
                """;
        Map<String, String> src = sources(service, USER_VO);
        src.put("src/main/resources/mapper/o.xml", """
                <mapper namespace="o">
                  <select id="list">SELECT * FROM O WHERE COMP_CD = #{compCd} ORDER BY #{sort}</select>
                  <insert id="i">INSERT INTO O (REG_ID) VALUES (#{regId})</insert>
                  <select id="brand">SELECT * FROM O WHERE BRAND_CD = #{brandCd}</select>
                </mapper>
                """);

        Draft draft = TraceRuleDrafter.draft(src);

        // regId는 값 자리에만 쓰이고, sort는 로그인 정보가 아니다. brandCd는 형 변환 없이 꺼냈지만 로그인 getter 접두어(getLogin)로 안다.
        assertThat(draft.scopeKeys()).extracting(Evidenced::value).containsExactly("compCd", "brandCd");
        assertThat(draft.scopeKeys().get(0).evidence())
                .startsWith("o.xml:2 #{compCd} ← S0.java:6 param.put(\"compCd\", user.getLoginCompCd())");
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
        TraceRules merged = TraceRules.empty();
        for (TraceRuleChange change : TraceRuleChangePlanner.plan(TraceRules.empty(), draft, "TEST").changes()) {
            merged = change.applyTo(merged);
        }

        List<TraceRuleDraftPreview.Change> changes = TraceRuleDraftPreview.changes(
                MybatisDollarTracer.trace(src, TraceRules.empty()), MybatisDollarTracer.trace(src, merged));

        assertThat(changes).singleElement().satisfies(c -> {
            assertThat(c.before()).isEqualTo(TraceSafety.CLIENT);
            assertThat(c.after()).isEqualTo(TraceSafety.SESSION_OVERWRITE);
        });
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
