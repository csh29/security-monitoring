package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleChange.Type;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.Draft;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.Evidenced;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleDrafter.OverwriteCandidate;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.FrameworkFact;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.SessionOverwrite;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TraceRuleChangePlannerTest {

    private static final List<FrameworkFact> FRAMEWORK = List.of(new FrameworkFact("웹", "Spring Boot 2.7.18", "pom.xml spring-boot 2.7.18"));

    /** 이 저장소 AOP가 paramData에 세션 값 둘(compCd, userId)과 세션 값이 아닌 것 하나(pgmId)를 넣는다. */
    private static Draft draft(List<Evidenced> scopeKeys, List<FrameworkFact> framework) {
        OverwriteCandidate c = new OverwriteCandidate("AddUser", "paramData", "HttpServletRequest",
                List.of(new Evidenced("compCd", "Util.java:10 put(compCd)"), new Evidenced("userId", "Util.java:11 put(userId)")),
                List.of(new Evidenced("pgmId", "Util.java:12 put(pgmId, statement)")), List.of("UserAspect.java:5 @Before(...)"));
        return new Draft(List.of(c), List.of(new Evidenced("UserVo", "A.java:3 (UserVo) session.getAttribute")),
                List.of(new Evidenced("getLogin", "UserVo getter 2개")), scopeKeys, framework, List.of(), List.of());
    }

    @Test
    void 새_시스템이면_장치와_로그인_정보는_확인_대기_구조_기록은_바로_반영() {
        TraceRuleChangePlanner.Plan plan = TraceRuleChangePlanner.plan(TraceRules.empty(),
                draft(List.of(new Evidenced("compCd", "t.xml:2 #{compCd}")), FRAMEWORK), "NEW_SYS");

        assertThat(plan.needsReview()).extracting(TraceRuleChange::type)
                .containsExactly(Type.ADD_OVERWRITE, Type.ADD_LOGIN_TYPE, Type.ADD_LOGIN_PREFIX, Type.ADD_SCOPE_KEY);
        assertThat(plan.automatic()).extracting(TraceRuleChange::type).containsExactly(Type.SET_FRAMEWORK);
        TraceRuleChange add = plan.needsReview().get(0);
        // 세션 값이 아닌 키는 넣지 않고 근거에만 남긴다.
        assertThat(add.values()).containsExactly("compCd", "userId");
        assertThat(add.evidence()).anyMatch(e -> e.startsWith("pgmId (세션 값 아님)"));
        assertThat(add.overwriteName()).isEqualTo("NEW_SYS @AddUser");
    }

    @Test
    void 기존_장치에_세션_값이_아닌_키가_들어_있으면_자동으로_뺀다() {
        TraceRules current = rules(Set.of("compCd", "userId", "pgmId"), "HttpServletRequest");

        TraceRuleChangePlanner.Plan plan = TraceRuleChangePlanner.plan(current, draft(List.of(), List.of()), "SYS");

        assertThat(plan.automatic()).singleElement().satisfies(c -> {
            assertThat(c.type()).isEqualTo(Type.REMOVE_OVERWRITE_KEYS);
            assertThat(c.values()).containsExactly("pgmId");
        });
        assertThat(plan.needsReview()).isEmpty();
    }

    /** 규칙은 여러 시스템이 같이 쓴다 — 다른 시스템 코드에서 넣는 키를 이 저장소에서 못 찾았다고 빼면 그 시스템이 오탐투성이가 된다. */
    @Test
    void 이_저장소_코드에서_못_찾은_키는_빼지_않는다() {
        TraceRules current = rules(Set.of("compCd", "userId", "brandCd"), "HttpServletRequest");

        TraceRuleChangePlanner.Plan plan = TraceRuleChangePlanner.plan(current, draft(List.of(), List.of()), "SYS");

        assertThat(plan.changes()).isEmpty();
    }

    @Test
    void 기존_장치에_없는_키와_첫_파라미터_조건_변경은_확인_대기() {
        TraceRules current = rules(Set.of("compCd"), null);

        TraceRuleChangePlanner.Plan plan = TraceRuleChangePlanner.plan(current, draft(List.of(), List.of()), "SYS");

        assertThat(plan.needsReview()).extracting(TraceRuleChange::type)
                .containsExactly(Type.ADD_OVERWRITE_KEYS, Type.SET_FIRST_PARAM);
        assertThat(plan.needsReview().get(0).values()).containsExactly("userId");
    }

    @Test
    void 구조_기록이_같으면_다시_쓰지_않는다() {
        TraceRules current = rules(Set.of("compCd", "userId"), "HttpServletRequest").withFramework("SYS", FRAMEWORK);

        assertThat(TraceRuleChangePlanner.plan(current, draft(List.of(), FRAMEWORK), "SYS").changes()).isEmpty();
        assertThat(TraceRuleChangePlanner.plan(current, draft(List.of(), FRAMEWORK), "OTHER").automatic())
                .extracting(TraceRuleChange::type).containsExactly(Type.SET_FRAMEWORK);
    }

    @Test
    void 위치가_두_단계_이상인_장치는_변경_없이_안내만() {
        OverwriteCandidate deep = new OverwriteCandidate("AddUser", "paramData.sub", null,
                List.of(new Evidenced("compCd", "U.java:1")), List.of(), List.of("A.java:1"));
        Draft draft = new Draft(List.of(deep), List.of(), List.of(), List.of(), List.of(), List.of(), List.of());

        TraceRuleChangePlanner.Plan plan = TraceRuleChangePlanner.plan(TraceRules.empty(), draft, "SYS");

        assertThat(plan.changes()).isEmpty();
        assertThat(plan.notes()).anyMatch(n -> n.contains("두 단계 이상"));
    }

    @Test
    void 변경은_두_번_적용해도_같다() {
        TraceRules current = rules(Set.of("compCd", "pgmId"), "HttpServletRequest");
        for (TraceRuleChange c : TraceRuleChangePlanner.plan(TraceRules.empty(),
                draft(List.of(new Evidenced("compCd", "t.xml:2")), FRAMEWORK), "SYS").changes()) {
            TraceRules once = c.applyTo(current);
            assertThat(c.applyTo(once)).as(c.type().name()).isEqualTo(once);
        }
    }

    /** 확인 대기는 DB에 JSON으로 두었다가 반영할 때 그대로 다시 적용한다. */
    @Test
    void JSON으로_저장했다_다시_읽어도_같은_변경이다() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        for (TraceRuleChange c : TraceRuleChangePlanner.plan(TraceRules.empty(),
                draft(List.of(new Evidenced("compCd", "t.xml:2")), FRAMEWORK), "SYS").changes()) {
            assertThat(mapper.readValue(mapper.writeValueAsString(c), TraceRuleChange.class)).isEqualTo(c);
        }
    }

    @Test
    void 같은_변경의_키는_줄_번호가_달라도_같다() {
        TraceRuleChange a = TraceRuleChangePlanner.plan(TraceRules.empty(), draft(List.of(), List.of()), "SYS").changes().get(0);
        TraceRuleChange b = new TraceRuleChange(a.type(), a.system(), a.annotation(), a.container(), a.requiredFirstParam(),
                a.values(), a.facts(), List.of("UserAspect.java:99 @Before(...)"));

        assertThat(b.key()).isEqualTo(a.key());
    }

    private static TraceRules rules(Set<String> keys, String firstParam) {
        return new TraceRules(List.of(new SessionOverwrite("x", "AddUser", "paramData", firstParam, keys)),
                Set.of("getLogin"), Set.of("UserVo"), Set.of(), Map.of());
    }
}
