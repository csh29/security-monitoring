package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecureCodeSnippetBuilderTest {

    @TempDir
    Path dir;

    private static SemgrepMatch match(String ruleId, String path, int start, int end) {
        return new SemgrepMatch(ruleId, "분류", "항목", "CWE-1", "HIGH", path, start, end, "메시지");
    }

    private DetectedFinding buildOne(String content, SemgrepMatch m) throws Exception {
        Path file = dir.resolve(m.filePath());
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return new SecureCodeSnippetBuilder(dir).build(List.of(m)).get(0);
    }

    @Test
    void 위에_줄이_추가돼도_지문은_같다() throws Exception {
        String before = "class A {\n  void f() { double d = Math.random(); }\n}\n";
        String after = "// 새 주석\n\nclass A {\n  void f() { double d = Math.random(); }\n}\n";

        DetectedFinding first = buildOne(before, match("kisa-insecure-random", "src/A.java", 2, 2));
        DetectedFinding second = buildOne(after, match("kisa-insecure-random", "src/A.java", 4, 4));

        assertThat(second.fingerprint()).isEqualTo(first.fingerprint());
        assertThat(second.startLine()).isEqualTo(4);
    }

    @Test
    void 들여쓰기만_바뀌어도_지문은_같고_코드가_바뀌면_다르다() throws Exception {
        DetectedFinding original = buildOne("x\n  int a = Math.random();\n", match("r", "A.java", 2, 2));
        DetectedFinding reformatted = buildOne("x\n        int a =   Math.random();\n", match("r", "A.java", 2, 2));
        DetectedFinding changed = buildOne("x\n  int b = Math.random();\n", match("r", "A.java", 2, 2));

        assertThat(reformatted.fingerprint()).isEqualTo(original.fingerprint());
        assertThat(changed.fingerprint()).isNotEqualTo(original.fingerprint());
    }

    @Test
    void 같은_파일의_같은_코드가_두번_걸리면_순번으로_구분한다() throws Exception {
        Files.writeString(dir.resolve("A.java"), "Math.random();\nMath.random();\n", StandardCharsets.UTF_8);

        List<DetectedFinding> detected = new SecureCodeSnippetBuilder(dir).build(List.of(
                match("r", "A.java", 1, 1), match("r", "A.java", 2, 2)));

        assertThat(detected.get(0).fingerprint()).isNotEqualTo(detected.get(1).fingerprint());
    }

    @Test
    void 코드_조각은_앞뒤_5줄이고_시작_줄번호를_같이_준다() throws Exception {
        StringBuilder content = new StringBuilder();
        for (int i = 1; i <= 20; i++) content.append("line").append(i).append('\n');

        DetectedFinding d = buildOne(content.toString(), match("r", "A.java", 10, 10));

        assertThat(d.snippetStartLine()).isEqualTo(5);
        assertThat(d.snippet().split("\n")).hasSize(11).startsWith("line5").endsWith("line15");
    }

    @Test
    void 비밀값_규칙은_조각에서_값을_가리고_값만_바뀌면_같은_건으로_본다() throws Exception {
        DetectedFinding d = buildOne("class A {\n  String dbPassword = \"P@ssw0rd123\";\n}\n",
                match("kisa-hardcoded-secret-java", "A.java", 2, 2));
        DetectedFinding other = buildOne("class A {\n  String dbPassword = \"another-secret\";\n}\n",
                match("kisa-hardcoded-secret-java", "A.java", 2, 2));

        assertThat(d.snippet()).doesNotContain("P@ssw0rd123").contains("dbPassword = \"****\"");
        assertThat(other.fingerprint()).isEqualTo(d.fingerprint());
    }

    @Test
    void 설정파일_비밀값도_가린다() throws Exception {
        DetectedFinding d = buildOne("spring.datasource.username=sa\nspring.datasource.password=admin1234\n",
                match("kisa-hardcoded-secret-config", "application.properties", 2, 2));

        assertThat(d.snippet()).doesNotContain("admin1234").contains("spring.datasource.password=****")
                .contains("spring.datasource.username=sa");
    }

    @Test
    void 주석_안의_비밀값도_가린다() throws Exception {
        DetectedFinding d = buildOne("class A {\n  // 운영 DB password: Prod#2024!\n  int x;\n}\n",
                match("kisa-hardcoded-secret-comment", "A.java", 2, 2));

        assertThat(d.snippet()).doesNotContain("Prod#2024!").contains("// 운영 DB password: ****");
    }

    @Test
    void 비밀값_규칙이_아니면_가리지_않는다() throws Exception {
        DetectedFinding d = buildOne("q = \"SELECT * FROM t WHERE a = \" + a;\n",
                match("kisa-sql-injection-java-concat", "A.java", 1, 1));

        assertThat(d.snippet()).contains("SELECT * FROM t");
    }

    @Test
    void UTF8이_아니면_MS949로_읽는다() {
        byte[] euckr = "// 한글 주석".getBytes(Charset.forName("MS949"));

        assertThat(SecureCodeSnippetBuilder.decode(euckr)).isEqualTo("// 한글 주석");
        assertThat(SecureCodeSnippetBuilder.decode("// 한글".getBytes(StandardCharsets.UTF_8))).isEqualTo("// 한글");
    }

    @Test
    void 저장소_밖_경로나_없는_파일은_빈_조각() throws Exception {
        Path project = Files.createDirectories(dir.resolve("project"));
        Files.writeString(dir.resolve("outside.java"), "secret\n", StandardCharsets.UTF_8);

        List<DetectedFinding> detected = new SecureCodeSnippetBuilder(project).build(List.of(
                match("r", "../outside.java", 1, 1), match("r", "missing.java", 1, 1)));

        assertThat(detected).allSatisfy(d -> assertThat(d.snippet()).isEmpty());
    }

    private DetectedFinding withAiContext(String content, SemgrepMatch m) throws Exception {
        Path file = dir.resolve(m.filePath());
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
        SecureCodeSnippetBuilder builder = new SecureCodeSnippetBuilder(dir);
        return builder.withAiContext(builder.build(List.of(m)).get(0));
    }

    /** class A { void f() { (줄 1~2) 아래로 int v0 .. v199 (줄 3~202) } (줄 203) } */
    private static String longMethod() {
        StringBuilder content = new StringBuilder("class A {\n  void f() {\n");
        for (int i = 0; i < 200; i++) content.append("    int v").append(i).append(" = ").append(i).append(";\n");
        return content.append("  }\n}\n").toString();
    }

    @Test
    void AI_문맥은_걸린_줄을_감싼_메서드_전체다() throws Exception {
        String content = "class A {\n"
                + "  void other() { int x = 1; }\n"
                + "  void f(String cmd) {\n"
                + "    String c = cmd.trim();\n"
                + "    Runtime.getRuntime().exec(c);\n"
                + "  }\n"
                + "}\n";

        DetectedFinding f = withAiContext(content, match("kisa-os-command-exec", "src/A.java", 5, 5));

        assertThat(f.aiContextStartLine()).isEqualTo(3);
        assertThat(f.aiContext()).startsWith("  void f(String cmd) {").endsWith("  }")
                .contains("cmd.trim()").doesNotContain("other()");
    }

    @Test
    void 메서드가_길면_걸린_줄이_가운데_오게_최대_줄_수만큼_자른다() throws Exception {
        DetectedFinding f = withAiContext(longMethod(), match("r", "A.java", 103, 103)); // 줄 103 = v100

        String[] lines = f.aiContext().split("\n");
        int hitIndex = 103 - f.aiContextStartLine();
        assertThat(lines).hasSize(SecureCodeSnippetBuilder.AI_CONTEXT_MAX_LINES);
        assertThat(lines[hitIndex]).contains("v100 ");
        assertThat(hitIndex).isBetween(35, 45);
    }

    @Test
    void 메서드_끝_근처면_메서드_범위_안에서_앞으로_당긴다() throws Exception {
        DetectedFinding f = withAiContext(longMethod(), match("r", "A.java", 200, 200));

        assertThat(f.aiContext().split("\n")).hasSize(SecureCodeSnippetBuilder.AI_CONTEXT_MAX_LINES);
        assertThat(f.aiContextStartLine() + SecureCodeSnippetBuilder.AI_CONTEXT_MAX_LINES - 1).isEqualTo(203);
    }

    @Test
    void 자바가_아니면_걸린_줄_앞뒤만_보내고_비밀값_규칙은_가린다() throws Exception {
        StringBuilder content = new StringBuilder();
        for (int i = 1; i <= 50; i++) content.append(i == 25 ? "db.password=secret123" : "key" + i + "=v").append("\n");

        DetectedFinding f = withAiContext(content.toString(), match("kisa-hardcoded-secret-config", "app.properties", 25, 25));

        assertThat(f.aiContextStartLine()).isEqualTo(25 - SecureCodeSnippetBuilder.AI_CONTEXT_LINES);
        assertThat(f.aiContext().split("\n")).hasSize(SecureCodeSnippetBuilder.AI_CONTEXT_LINES * 2 + 1);
        assertThat(f.aiContext()).contains("db.password=****").doesNotContain("secret123");
    }
}
