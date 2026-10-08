package com.sjinc.securitymonitor.service.securecode.semgrep;

import com.sjinc.securitymonitor.exception.SecureCodeScanException;
import com.sjinc.securitymonitor.service.securecode.trace.TraceSink;
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

    @Test
    void 규칙의_연계_추적_선언을_모은다() throws Exception {
        Files.writeString(dir.resolve("a.yml"), """
                rules:
                  - id: exec
                    metadata:
                      cwe: CWE-78
                      trace: arguments
                  - id: url
                    metadata:
                      trace: first-argument
                      trace_fixed_host: true
                  - id: upload
                    metadata:
                      trace: value
                  - id: plain
                    metadata:
                      cwe: CWE-330
                """);

        RuleSetLoader.RuleSet ruleSet = new RuleSetLoader().load(dir);

        assertThat(ruleSet.sinks()).containsOnlyKeys("exec", "url", "upload");
        assertThat(ruleSet.sinks().get("exec")).isEqualTo(new TraceSink(TraceSink.Target.ARGUMENTS, false));
        assertThat(ruleSet.sinks().get("url")).isEqualTo(new TraceSink(TraceSink.Target.FIRST_ARGUMENT, true));
        assertThat(ruleSet.sinks().get("upload").target()).isEqualTo(TraceSink.Target.VALUE);
    }

    @Test
    void 연계_추적_선언이_틀리면_점검을_실패시킨다() throws Exception {
        // 조용히 넘기면 그 규칙의 탐지가 판정 없이 저장돼 "추적이 안전하다고 본 것"과 구분이 안 된다.
        Files.writeString(dir.resolve("a.yml"), "rules:\n  - id: exec\n    metadata:\n      trace: argument\n");

        assertThatThrownBy(() -> new RuleSetLoader().load(dir))
                .isInstanceOf(SecureCodeScanException.class).hasMessageContaining("exec").hasMessageContaining("a.yml");
    }

    @Test
    void 실제_규칙_폴더의_실행_지점_규칙은_연계_추적을_선언한다() throws Exception {
        assertThat(new RuleSetLoader().load(Path.of("../securecode/rules")).sinks()).containsOnlyKeys(
                "kisa-os-command-exec", "kisa-os-command-injection-request", "kisa-path-traversal-download",
                "kisa-path-traversal-dynamic-path", "kisa-ssrf-dynamic-url", "kisa-sql-injection-java-concat", "kisa-file-upload-save");
    }
}
