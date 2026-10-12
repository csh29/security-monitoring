package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class SecureCodeSystemContextTest {

    @Test
    void 그_시스템의_구조와_공통_시스템별_추적_규칙을_합쳐_보인다() {
        TraceRules rules = new TraceRules(List.of(), Set.of("getLogin"), Set.of(), Set.of("loginCompCd"),
                Map.of("CRM", List.of(new TraceRules.FrameworkFact("필터", "XssFilter", "web.xml <filter-class>a.XssFilter")),
                        "OTHER", List.of(new TraceRules.FrameworkFact("인터셉터", "OtherInterceptor", "x"))),
                Map.of("CRM", new TraceRules.SystemRules(Set.of(), Set.of("LoginUserVo"), Set.of("brndzCd"))));

        List<String> lines = SecureCodeSystemContext.lines(rules, "CRM");

        assertThat(lines).contains("필터: XssFilter — web.xml <filter-class>a.XssFilter")
                .noneMatch(line -> line.contains("OtherInterceptor"))      // 다른 시스템 구조는 싣지 않는다
                .anyMatch(line -> line.contains("LoginUserVo"))           // 시스템별 로그인 정보 이름
                .anyMatch(line -> line.contains("getLogin"))              // 공통 getter 접두어
                .anyMatch(line -> line.contains("loginCompCd") && line.contains("brndzCd"));
    }

    @Test
    void 비밀값은_가리고_줄_수와_길이를_제한한다() {
        List<TraceRules.FrameworkFact> facts = IntStream.range(0, 60)
                .mapToObj(i -> new TraceRules.FrameworkFact("설정", "a" + i, "password=hunter2" + "x".repeat(400))).toList();
        TraceRules rules = new TraceRules(List.of(), Set.of(), Set.of(), Set.of(), Map.of("CRM", facts));

        List<String> lines = SecureCodeSystemContext.lines(rules, "CRM");

        assertThat(lines).hasSize(SecureCodeSystemContext.MAX_LINES)
                .allMatch(line -> !line.contains("hunter2"));
        assertThat(SecureCodeSystemContext.lines(rules, null)).isEmpty();
        assertThat(SecureCodeSystemContext.lines(rules, "NONE")).isEmpty();
    }
}
