package com.sjinc.securitymonitor.service.securecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RuleSetLoaderTest {

    @TempDir
    Path dir;

    @Test
    void yml의_규칙id를_모으고_테스트_예제_파일은_무시한다() throws Exception {
        Files.writeString(dir.resolve("a.yml"), "rules:\n  - id: rule-a\n  - id: rule-b\n");
        Files.writeString(dir.resolve("b.yaml"), "rules:\n  - id: rule-c\n");
        Files.writeString(dir.resolve("a.java"), "class A {}");

        RuleSetLoader.RuleSet ruleSet = new RuleSetLoader().load(dir);

        assertThat(ruleSet.ruleIds()).containsExactly("rule-a", "rule-b", "rule-c");
        assertThat(ruleSet.version()).hasSize(12);
    }

    @Test
    void 규칙_내용이_바뀌면_버전이_바뀐다() throws Exception {
        Files.writeString(dir.resolve("a.yml"), "rules:\n  - id: rule-a\n");
        String before = new RuleSetLoader().load(dir).version();

        Files.writeString(dir.resolve("a.yml"), "rules:\n  - id: rule-a\n    message: changed\n");

        assertThat(new RuleSetLoader().load(dir).version()).isNotEqualTo(before);
    }

    @Test
    void 규칙이_없거나_폴더가_없으면_점검을_실패시킨다() throws Exception {
        Files.writeString(dir.resolve("empty.yml"), "rules: []\n");

        assertThatThrownBy(() -> new RuleSetLoader().load(dir)).isInstanceOf(SecureCodeScanException.class);
        assertThatThrownBy(() -> new RuleSetLoader().load(dir.resolve("none"))).isInstanceOf(SecureCodeScanException.class);
    }

    @Test
    void 저장소의_실제_규칙_폴더를_읽을_수_있다() throws Exception {
        // 테스트는 backend/에서 돈다 — 서버 기본값 securecode.rules-dir(../securecode/rules)과 같은 기준.
        Path rules = Path.of("../securecode/rules");

        assertThat(new RuleSetLoader().load(rules).ruleIds())
                .contains("kisa-sql-injection-mybatis-dollar", "kisa-hardcoded-secret-config", "kisa-insecure-random");
    }
}
