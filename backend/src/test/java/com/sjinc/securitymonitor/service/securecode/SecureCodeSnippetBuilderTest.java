package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SemgrepMatch;
import com.sjinc.securitymonitor.dto.securecode.TraceStepCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

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

    /**
     * AI 관련 코드 — 탐지 메서드가 부르는 헬퍼와 연계 추적 경로의 메서드를 .java만 같이 보낸다. 비밀값을 문자열로 대입하는 메서드와
     * 설정 파일은 보내지 않는다(이름은 요청값 같지만 상수를 돌려주는 헬퍼를 AI가 못 봐서 틀렸다 — OWASP Benchmark).
     */
    @Test
    void AI_관련_코드는_부르는_헬퍼와_추적_경로_메서드를_java만_보낸다() throws Exception {
        String trap = """
                package p;
                public class Trap {
                    public void doPost(HttpServletRequest request) {
                        String v = new Helper().getTheValue("x");
                        String key = new Keys().apiKey();
                        statement.execute("SELECT * FROM U WHERE P='" + v + "'");
                    }
                }
                """;
        String helper = """
                package p;
                public class Helper {
                    public String getTheValue(String p) {
                        return "bar";
                    }
                }
                """;
        String keys = """
                package p;
                public class Keys {
                    public String apiKey() {
                        String apiKey = "sk-live-123456";
                        return apiKey;
                    }
                }
                """;
        String controller = """
                package p;
                public class Ctl {
                    public void handle() {
                        new Trap().doPost(null);
                    }
                }
                """;
        Map<String, String> sources = new java.util.LinkedHashMap<>();
        sources.put("src/main/java/p/Trap.java", trap);
        sources.put("src/main/java/p/Helper.java", helper);
        sources.put("src/main/java/p/Keys.java", keys);
        sources.put("src/main/java/p/Ctl.java", controller);
        sources.put("src/main/resources/application.properties", "db.password=hunter2\n");
        for (Map.Entry<String, String> e : sources.entrySet()) {
            Path file = dir.resolve(e.getKey());
            Files.createDirectories(file.getParent());
            Files.writeString(file, e.getValue(), StandardCharsets.UTF_8);
        }
        SecureCodeSnippetBuilder builder = new SecureCodeSnippetBuilder(dir);
        DetectedFinding f = builder.withAiContext(builder.build(List.of(match("kisa-sql-injection-java-concat", "src/main/java/p/Trap.java", 6, 6))).get(0))
                .withTrace("MEDIUM", "UNKNOWN", "Ctl.java:4 new Trap().doPost(null)\napplication.properties:1 db.password\nTrap.java:6 statement.execute(...)");
        Map<String, List<String>> pathsByFileName = Map.of(
                "Ctl.java", List.of("src/main/java/p/Ctl.java"), "Trap.java", List.of("src/main/java/p/Trap.java"),
                "application.properties", List.of("src/main/resources/application.properties"));

        List<com.sjinc.securitymonitor.dto.securecode.AiRelatedCode> related = builder.aiRelatedCode(f,
                com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.fromSources(sources), pathsByFileName);

        // 추적 경로의 컨트롤러 메서드, 탐지 메서드가 부르는 헬퍼. 탐지 메서드 자신(이미 [코드])·설정 파일·키를 대입하는 메서드는 빠진다.
        assertThat(related).extracting(com.sjinc.securitymonitor.dto.securecode.AiRelatedCode::path)
                .containsExactly("src/main/java/p/Ctl.java", "src/main/java/p/Helper.java");
        assertThat(related.get(1).code()).contains("return \"bar\";");
        assertThat(related.get(1).startLine()).isEqualTo(3);
        assertThat(related.get(1).reason()).contains("Helper.getTheValue()");
        assertThat(related).noneMatch(r -> r.code().contains("sk-live") || r.code().contains("hunter2"));
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

    @Test
    void 자바_조각은_걸린_줄을_감싼_메서드_전체이고_길면_80줄로_자른다() throws Exception {
        String code = "class A {\n  void f(String p) {\n    String a = p;\n    String b = a;\n    String c = b;\n"
                + "    String d = c;\n    String e = d;\n    String sql = \"x\" + e;\n    run(sql);\n  }\n}\n";
        DetectedFinding d = buildOne(code, match("r", "src/A.java", 9, 9));
        assertThat(d.snippetStartLine()).isEqualTo(2);
        assertThat(d.snippet().split("\n")).hasSize(9).startsWith("  void f(String p) {").endsWith("  }");

        DetectedFinding big = buildOne(longMethod(), match("r", "src/A.java", 100, 100));
        assertThat(big.snippet().split("\n")).hasSize(SecureCodeSnippetBuilder.SNIPPET_MAX_LINES);
        assertThat(big.snippetStartLine()).isLessThan(100).isGreaterThan(100 - SecureCodeSnippetBuilder.SNIPPET_MAX_LINES);
    }

    @Test
    void 매퍼_XML_조각은_걸린_줄을_감싼_구문이다() throws Exception {
        String xml = "<mapper>\n  <select id=\"a\">\n    SELECT 1\n  </select>\n  <select id=\"b\">\n    SELECT *\n"
                + "    FROM t\n    WHERE x = ${x}\n  </select>\n</mapper>\n";
        DetectedFinding d = buildOne(xml, match("r", "src/m.xml", 8, 8));
        assertThat(d.snippetStartLine()).isEqualTo(5);
        assertThat(d.snippet().split("\n")).hasSize(5).startsWith("  <select id=\"b\">").endsWith("  </select>");
    }

    @Test
    void 연계_추적_근거_걸음마다_그_줄_주변_코드를_붙인다() throws Exception {
        Files.createDirectories(dir.resolve("a"));
        Files.createDirectories(dir.resolve("b"));
        StringBuilder controller = new StringBuilder();
        for (int i = 1; i <= 20; i++) controller.append("c").append(i).append('\n');
        Files.writeString(dir.resolve("a/C.java"), controller, StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("a/S.java"), "s1\ns2\n", StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("b/S.java"), "x1\nx2\n", StandardCharsets.UTF_8);
        DetectedFinding f = new DetectedFinding("fp", "r", "분류", "항목", "CWE-1", "HIGH", "a/S.java", 2, 2, "m",
                "s", 1, "CLIENT", "C.java:10 POST /x — 클라이언트가 보낸 값\n파라미터 없이 실행\nS.java:1 run(sql)\nZ.java:1 없는 파일",
                null, null);
        Map<String, List<String>> byName = Map.of("C.java", List.of("a/C.java"), "S.java", List.of("a/S.java", "b/S.java"));

        List<TraceStepCode> code = new SecureCodeSnippetBuilder(dir).traceCode(f, byName);

        assertThat(code).hasSize(4);
        assertThat(code.get(0).path()).isEqualTo("a/C.java");
        assertThat(code.get(0).line()).isEqualTo(10);
        assertThat(code.get(0).startLine()).isEqualTo(10 - SecureCodeSnippetBuilder.TRACE_CONTEXT_LINES);
        assertThat(code.get(0).code().split("\n")).hasSize(SecureCodeSnippetBuilder.TRACE_CONTEXT_LINES * 2 + 1).contains("c10");
        assertThat(code.get(1)).isNull();                          // 파일·줄이 없는 걸음
        assertThat(code.get(2).path()).isEqualTo("a/S.java");     // 동명 파일 중 탐지 파일 자신
        assertThat(code.get(3)).isNull();                          // 찾지 못한 파일
    }

    @Test
    void 동명_파일은_탐지_파일과_경로가_가장_많이_겹치는_것을_고르고_못_고르면_빈다() {
        Map<String, List<String>> byName = Map.of("U.java", List.of("m1/src/U.java", "m2/src/U.java"));
        assertThat(SecureCodeSnippetBuilder.pickPath("U.java", "m2/src/X.java", byName)).isEqualTo("m2/src/U.java");
        assertThat(SecureCodeSnippetBuilder.pickPath("U.java", "m3/src/X.java", byName)).isNull();
    }
}
