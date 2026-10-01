package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.dto.ai.CodeUsageView;
import com.sjinc.cvemonitor.dto.ai.UpgradeImpactRequest.BreakingChange;
import com.sjinc.cvemonitor.dto.scan.SourceUsage;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CodeUsageMatcherTest {

    private static final SourceUsage USAGE = new SourceUsage(
            Map.of("org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter", 2,
                    "javax.servlet.http.HttpServletRequest", 5,
                    "org.springframework.context.annotation.Configuration", 7,
                    "com.fasterxml.jackson.databind.*", 1),
            Set.of("spring.redis.host", "server.max-http-header-size", "server.port"),
            40);

    private static BreakingChange change(String... symbols) {
        return new BreakingChange("요약", "https://example.com", List.of(symbols));
    }

    private static CodeUsageView.Item only(BreakingChange change) {
        return CodeUsageMatcher.match(List.of(change), USAGE).items().get(0);
    }

    @Test
    void 정확한_클래스_이름이_import에_있으면_사용_발견() {
        CodeUsageView.Item item = only(change(
                "org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter"));

        assertThat(item.status()).isEqualTo(CodeUsageMatcher.USED);
        assertThat(item.matches()).singleElement().asString().contains("파일 2곳");
    }

    @Test
    void 영향받는_패키지에서_import하면_사용_발견() {
        assertThat(only(change("javax.servlet")).status()).isEqualTo(CodeUsageMatcher.USED);
        // 와일드카드 import가 그 패키지 아래를 통째로 가져와도 마찬가지다.
        assertThat(only(change("com.fasterxml.jackson")).status()).isEqualTo(CodeUsageMatcher.USED);
    }

    @Test
    void 짧은_이름만_맞으면_가능성으로_낮춘다() {
        // Configuration은 이름만 같은 다른 패키지의 클래스일 수 있다.
        assertThat(only(change("Configuration")).status()).isEqualTo(CodeUsageMatcher.POSSIBLE);
    }

    @Test
    void 와일드카드_import_패키지의_클래스는_가능성() {
        assertThat(only(change("com.fasterxml.jackson.databind.ObjectMapper")).status()).isEqualTo(CodeUsageMatcher.POSSIBLE);
    }

    @Test
    void 설정_키는_정확히_같거나_이름이_바뀐_접두어면_사용_발견() {
        assertThat(only(change("spring.redis")).status()).isEqualTo(CodeUsageMatcher.USED);
        // Spring relaxed binding — kebab과 camel은 같은 키다.
        assertThat(only(change("server.maxHttpHeaderSize")).status()).isEqualTo(CodeUsageMatcher.USED);
    }

    @Test
    void 점_없는_이름이나_클래스_이름은_설정_키와_대조하지_않는다() {
        // "server"를 접두어로 비교하면 server.port 같은 모든 키에 걸리고, 클래스 Server는 대소문자 무시 비교에서 오인된다.
        assertThat(only(change("server")).status()).isEqualTo(CodeUsageMatcher.NOT_FOUND);
        assertThat(only(change("Server")).status()).isEqualTo(CodeUsageMatcher.NOT_FOUND);
    }

    @Test
    void 메서드가_붙어_와도_클래스로_대조한다() {
        assertThat(CodeUsageMatcher.toTypeName("org.x.Foo#bar")).isEqualTo("org.x.Foo");
        assertThat(CodeUsageMatcher.toTypeName("org.x.Foo.bar()")).isEqualTo("org.x.Foo");
        assertThat(CodeUsageMatcher.toTypeName("org.x.Foo.bar")).isEqualTo("org.x.Foo");
        assertThat(CodeUsageMatcher.toTypeName("javax.servlet")).isEqualTo("javax.servlet");
        assertThat(CodeUsageMatcher.toTypeName("spring.redis.host")).isEqualTo("spring.redis.host");
        assertThat(only(change("javax.servlet.http.HttpServletRequest#getParameter")).status()).isEqualTo(CodeUsageMatcher.USED);
    }

    @Test
    void 이름이_없는_변경은_판단_불가이고_전체도_안_보임이라_하지_않는다() {
        CodeUsageView view = CodeUsageMatcher.match(
                List.of(change(), change("org.unused.Thing")), USAGE);

        assertThat(view.items()).extracting(CodeUsageView.Item::status)
                .containsExactly(CodeUsageMatcher.UNKNOWN, CodeUsageMatcher.NOT_FOUND);
        // 일부만 "안 보임"이어도 전체를 "안 보임"이라 할 수 없다.
        assertThat(view.status()).isEqualTo(CodeUsageMatcher.UNKNOWN);
    }

    @Test
    void 이전_형식의_분석_결과처럼_symbols가_null이면_판단_불가() {
        CodeUsageView view = CodeUsageMatcher.match(List.of(new BreakingChange("요약", "https://x", null)), USAGE);

        assertThat(view.status()).isEqualTo(CodeUsageMatcher.UNKNOWN);
    }

    @Test
    void 하나라도_사용이면_전체가_사용_발견() {
        CodeUsageView view = CodeUsageMatcher.match(List.of(change("org.unused.Thing"), change("javax.servlet")), USAGE);

        assertThat(view.status()).isEqualTo(CodeUsageMatcher.USED);
    }

    @Test
    void 소스_목록이_없으면_전부_판단_불가와_이유() {
        CodeUsageView noUsage = CodeUsageMatcher.match(List.of(change("javax.servlet")), null);
        CodeUsageView noFiles = CodeUsageMatcher.match(List.of(change("javax.servlet")),
                new SourceUsage(Map.of(), Set.of(), 0));

        assertThat(noUsage.status()).isEqualTo(CodeUsageMatcher.UNKNOWN);
        assertThat(noUsage.reason()).contains("다시 스캔");
        assertThat(noFiles.items()).extracting(CodeUsageView.Item::status).containsExactly(CodeUsageMatcher.UNKNOWN);
    }
}
