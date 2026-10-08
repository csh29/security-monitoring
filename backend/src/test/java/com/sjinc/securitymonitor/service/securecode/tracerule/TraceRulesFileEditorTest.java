package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleChange.Type;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.FrameworkFact;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TraceRulesFileEditorTest {

    /** 실제 trace-rules.yml과 같은 모양 — 항목 안 주석, keys는 한 줄 목록, userScopeKeys는 여러 줄 목록. */
    private static final String FILE = """
            # 머리 주석
            sessionOverwrites:
              # 회사 프레임워크 — regPgmId는 세션 값이 아니라 넣지 않는다.
              - name: sjinc 프레임워크 @AddUserInfo
                annotation: AddUserInfo
                container: paramData
                requiredFirstParam: HttpServletRequest
                keys: [loginCompCd, loginUserId, regPgmId]

            # 로그인 getter
            loginMethodPrefixes: [getLogin]

            loginTypeNames: [LoginUser]

            # 사용자 범위 키
            userScopeKeys:
              # 회사 프레임워크 키
              - loginCompCd
            """;
    private static final String STAMP = "2026-10-08 자동 반영";

    @Test
    void 세션_값이_아닌_키를_빼고_주석은_그대로_둔다() {
        String edited = TraceRulesFileEditor.apply(FILE, List.of(
                change(Type.REMOVE_OVERWRITE_KEYS, "AddUserInfo", "paramData", null, "regPgmId")), STAMP);

        assertThat(edited).contains("    keys: [loginCompCd, loginUserId]\n")
                .contains("    # 2026-10-08 자동 반영: [regPgmId] 제외(세션 값 아님) — regPgmId ← Util.java:12")
                .contains("  # 회사 프레임워크 — regPgmId는 세션 값이 아니라 넣지 않는다.")
                .contains("# 머리 주석").contains("# 로그인 getter").contains("  # 회사 프레임워크 키");
        assertThat(TraceRules.parse(edited).sessionOverwrites().get(0).keys()).containsExactly("loginCompCd", "loginUserId");
    }

    @Test
    void 새_장치는_세션_덮어쓰기_섹션_끝에_근거_주석과_함께_넣는다() {
        String edited = TraceRulesFileEditor.apply(FILE, List.of(
                change(Type.ADD_OVERWRITE, "UserInject", null, "HttpServletRequest", "compCd", "userId")), STAMP);

        TraceRules rules = TraceRules.parse(edited);
        assertThat(rules.sessionOverwrites()).hasSize(2);
        assertThat(rules.sessionOverwrites().get(1)).satisfies(o -> {
            assertThat(o.name()).isEqualTo("NEW_SYS @UserInject");
            assertThat(o.container()).isNull();
            assertThat(o.requiredFirstParam()).isEqualTo("HttpServletRequest");
            assertThat(o.keys()).containsExactly("compCd", "userId");
        });
        // 섹션 안(다음 최상위 주석 앞)에 들어간다.
        assertThat(edited.indexOf("- name: \"NEW_SYS @UserInject\"")).isLessThan(edited.indexOf("# 로그인 getter"));
        assertThat(edited).contains("  # 2026-10-08 자동 반영 — NEW_SYS 점검 초안. 근거:", "  #   compCd ← Util.java:10");
    }

    @Test
    void 한_줄_목록과_여러_줄_목록에_더한다() {
        String edited = TraceRulesFileEditor.apply(FILE, List.of(
                change(Type.ADD_LOGIN_TYPE, null, null, null, "MemberSession"),
                change(Type.ADD_SCOPE_KEY, null, null, null, "loginBrndzCd")), STAMP);

        TraceRules rules = TraceRules.parse(edited);
        assertThat(rules.loginTypeNames()).containsExactly("LoginUser", "MemberSession");
        assertThat(rules.userScopeKeys()).containsExactly("loginCompCd", "loginBrndzCd");
        assertThat(edited).contains("loginTypeNames: [LoginUser, MemberSession]", "  - loginBrndzCd");
    }

    @Test
    void 프레임워크_구조는_맨_끝에_시스템별로_쓰고_다시_쓰면_바꾼다() {
        List<FrameworkFact> v1 = List.of(new FrameworkFact("웹", "Spring Boot 2.7.18", "pom.xml spring-boot 2.7.18"));
        List<FrameworkFact> v2 = List.of(new FrameworkFact("웹", "Spring Boot 3.3.4", "pom.xml spring-boot 3.3.4"),
                new FrameworkFact("필터", "요청 래퍼 XssWrapper", "XssWrapper.java XssWrapper — \"따옴표\": #샵"));

        String once = TraceRulesFileEditor.apply(FILE, List.of(framework("CRM_BACK", v1), framework("ERP", v1)), STAMP);
        String twice = TraceRulesFileEditor.apply(once, List.of(framework("CRM_BACK", v2),
                change(Type.ADD_LOGIN_PREFIX, null, null, null, "getMember")), STAMP);

        TraceRules rules = TraceRules.parse(twice);
        assertThat(rules.frameworks().get("CRM_BACK")).isEqualTo(v2);
        assertThat(rules.frameworks().get("ERP")).isEqualTo(v1);
        assertThat(twice.split("\nframeworks:", -1)).hasSize(2); // 섹션이 하나뿐
        assertThat(twice.indexOf("frameworks:")).isGreaterThan(twice.indexOf("userScopeKeys:"));
        assertThat(rules.loginMethodPrefixes()).containsExactly("getLogin", "getMember");
    }

    /** 구조 기록만 바뀌었는데 규칙셋 버전이 바뀌면 점검 이력에서 "판정 기준이 바뀌었다"로 잘못 읽힌다. */
    @Test
    void 판정에_쓰는_부분은_구조_기록과_무관하다() {
        String withFramework = TraceRulesFileEditor.apply(FILE, List.of(framework("CRM_BACK",
                List.of(new FrameworkFact("웹", "Spring Boot", "App.java App")))), STAMP);

        assertThat(TraceRulesFileEditor.judgmentPart(withFramework)).isEqualTo(TraceRulesFileEditor.judgmentPart(FILE));
        assertThat(TraceRulesFileEditor.judgmentPart(FILE.replace("\n", "\r\n"))).isEqualTo(TraceRulesFileEditor.judgmentPart(FILE));
    }

    @Test
    void 이미_반영된_변경은_파일을_바꾸지_않는다() {
        String edited = TraceRulesFileEditor.apply(FILE, List.of(change(Type.ADD_SCOPE_KEY, null, null, null, "loginCompCd")), STAMP);

        assertThat(edited).isEqualTo(FILE);
    }

    @Test
    void 파일이_없으면_섹션을_만든다() {
        String edited = TraceRulesFileEditor.apply("", List.of(
                change(Type.ADD_OVERWRITE, "AddUser", "paramData", null, "compCd"),
                change(Type.ADD_SCOPE_KEY, null, null, null, "compCd")), STAMP);

        TraceRules rules = TraceRules.parse(edited);
        assertThat(rules.sessionOverwrites()).singleElement().satisfies(o -> assertThat(o.keys()).containsExactly("compCd"));
        assertThat(rules.userScopeKeys()).containsExactly("compCd");
    }

    @Test
    void 예상과_다른_모양이면_고치지_않고_실패한다() {
        String multiLineKeys = FILE.replace("    keys: [loginCompCd, loginUserId, regPgmId]",
                "    keys:\n      - loginCompCd\n      - regPgmId");

        assertThatThrownBy(() -> TraceRulesFileEditor.apply(multiLineKeys, List.of(
                change(Type.REMOVE_OVERWRITE_KEYS, "AddUserInfo", "paramData", null, "regPgmId")), STAMP))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("직접 반영");
    }

    @Test
    void 첫_파라미터_조건을_바꾸고_없앤다() {
        String changed = TraceRulesFileEditor.apply(FILE, List.of(
                change(Type.SET_FIRST_PARAM, "AddUserInfo", "paramData", "ServletRequest")), STAMP);
        String removed = TraceRulesFileEditor.apply(FILE, List.of(
                change(Type.SET_FIRST_PARAM, "AddUserInfo", "paramData", null)), STAMP);

        assertThat(TraceRules.parse(changed).sessionOverwrites().get(0).requiredFirstParam()).isEqualTo("ServletRequest");
        assertThat(TraceRules.parse(removed).sessionOverwrites().get(0).requiredFirstParam()).isNull();
    }

    /** 실제 설정 파일에 써도 지금 규칙이 그대로 읽혀야 한다(주석·모양이 편집기와 맞는지). */
    @Test
    void 실제_trace_rules_yml에_구조_기록을_써도_규칙은_그대로다() throws Exception {
        String real = Files.readString(Path.of("../securecode/trace-rules.yml"));
        TraceRules before = TraceRules.parse(real);

        String edited = TraceRulesFileEditor.apply(real, List.of(framework("CRM_BACK",
                List.of(new FrameworkFact("웹", "Spring Boot", "App.java App")))), STAMP);

        TraceRules after = TraceRules.parse(edited);
        assertThat(after.sessionOverwrites()).isEqualTo(before.sessionOverwrites());
        assertThat(after.userScopeKeys()).isEqualTo(before.userScopeKeys());
        assertThat(after.frameworks()).containsKey("CRM_BACK");
    }

    private static TraceRuleChange change(Type type, String annotation, String container, String firstParam, String... values) {
        return new TraceRuleChange(type, "NEW_SYS", annotation, container, firstParam, List.of(values), null,
                List.of("UserAspect.java:5 @Before(...)", values.length > 0 ? values[0] + " ← Util.java:" + (type == Type.ADD_OVERWRITE ? 10 : 12) : "x"));
    }

    private static TraceRuleChange framework(String system, List<FrameworkFact> facts) {
        return new TraceRuleChange(Type.SET_FRAMEWORK, system, null, null, null, List.of(), facts, List.of());
    }
}
