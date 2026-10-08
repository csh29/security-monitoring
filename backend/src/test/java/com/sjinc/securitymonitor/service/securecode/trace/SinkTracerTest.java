package com.sjinc.securitymonitor.service.securecode.trace;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.semgrep.RuleSetLoader;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SinkTracerTest {

    /** 실제 규칙 파일의 추적 선언(metadata.trace) — 선언이 빠지거나 틀리면 여기서 깨진다. */
    private static final Map<String, TraceSink> SINKS = loadSinks();

    /** 컨트롤러가 받은 값을 서비스가 위험 호출에 쓰는 사내 구조 — Semgrep taint(한 메서드 안)로는 이어지지 않는다. */
    private static final String CONTROLLER = """
            package p;
            import java.util.*;
            @RestController
            class C {
                private final S s;
                @GetMapping("/proxy") public Object proxy(@RequestParam String url) { return s.fetch(url); }
                @GetMapping("/items") public Object items(@RequestParam String q) { return s.items(q); }
                @PostMapping("/upload") public void upload(@RequestPart("file") MultipartFile file) throws Exception { s.save(file); }
                @PostMapping("/upload2") public void upload2(@RequestPart("file") MultipartFile file) throws Exception { s.saveSafe(file); }
            }
            """;

    private static final String SERVICE = """
            package p;
            import java.io.File;
            import java.net.URL;
            import java.util.UUID;
            class S {
                private static final String API_BASE = "https://api.example.com";
                private RestTemplate restTemplate;
                @Value("${batch.url}")
                private String batchUrl;
                @Value("${upload.dir}")
                private String uploadDir;

                Object fetch(String url) {
                    return restTemplate.getForObject(url, String.class);
                }
                Object callBatch() {
                    return restTemplate.postForObject(batchUrl, null, String.class);
                }
                Object items(String q) throws Exception {
                    String u = API_BASE + "/v1/items?q=" + q;
                    return new URL(u);
                }
                void save(MultipartFile file) throws Exception {
                    file.transferTo(new File(uploadDir, file.getOriginalFilename()));
                }
                void saveSafe(MultipartFile file) throws Exception {
                    file.transferTo(new File(uploadDir, UUID.randomUUID().toString()));
                }
                void ping() throws Exception {
                    String cmd = "hostname";
                    Runtime.getRuntime().exec(cmd);
                }
            }
            """;

    @Test
    void 서비스의_위험_호출을_컨트롤러까지_따라가_판정한다() {
        Map<String, SinkTracer.SinkVerdict> v = trace(
                finding("kisa-ssrf-dynamic-url", 14, "restTemplate.getForObject("),    // fetch: 요청값 url
                finding("kisa-ssrf-dynamic-url", 17, "restTemplate.postForObject("),   // callBatch: @Value 설정값
                finding("kisa-ssrf-dynamic-url", 21, "new URL("),                      // items: 고정 호스트 + 쿼리
                finding("kisa-file-upload-save", 24, "new File("),                     // save: 원래 파일명(저장 위치만 가리킨다)
                finding("kisa-file-upload-save", 27, "new File("),                     // saveSafe: UUID
                finding("kisa-os-command-exec", 31, "Runtime.getRuntime().exec("));   // ping: 상수 명령

        assertThat(v.get("kisa-ssrf-dynamic-url:14").safety()).isEqualTo(TraceSafety.CLIENT);
        assertThat(v.get("kisa-ssrf-dynamic-url:14").evidence()).anyMatch(e -> e.contains("/proxy"));
        assertThat(v.get("kisa-ssrf-dynamic-url:17").safety()).isEqualTo(TraceSafety.SERVER_SET);
        assertThat(v.get("kisa-ssrf-dynamic-url:17").evidence()).anyMatch(e -> e.contains("@Value"));
        assertThat(v.get("kisa-ssrf-dynamic-url:21").safety()).isEqualTo(TraceSafety.SERVER_SET);
        assertThat(v.get("kisa-ssrf-dynamic-url:21").evidence()).anyMatch(e -> e.contains("호스트 고정"));
        assertThat(v.get("kisa-file-upload-save:24").safety()).isEqualTo(TraceSafety.CLIENT);
        assertThat(v.get("kisa-file-upload-save:27").safety()).isEqualTo(TraceSafety.SERVER_SET);
        assertThat(v.get("kisa-os-command-exec:31").safety()).isEqualTo(TraceSafety.SERVER_SET);
    }

    @Test
    void 판정으로_등급을_다시_매기고_못_찾은_탐지는_그대로_둔다() {
        DetectedFinding noColumns = new DetectedFinding("no-columns", "kisa-ssrf-dynamic-url", "분류", "항목", "CWE-1", "MEDIUM",
                "src/main/java/p/S.java", 14, 14, "메시지", "code", 14, null, null, null, null);
        List<DetectedFinding> detected = List.of(
                finding("kisa-ssrf-dynamic-url", 14, "restTemplate.getForObject("),
                finding("kisa-ssrf-dynamic-url", 17, "restTemplate.postForObject("),
                noColumns,                                                               // 범위를 모르면 판정하지 않는다
                finding("kisa-insecure-random", 14, "restTemplate.getForObject("));    // 추적 선언이 없는 규칙

        List<DetectedFinding> applied = SinkTracer.apply(detected, new SinkTracer(index(), TraceRules.empty(), SINKS).trace(detected));

        assertThat(applied).extracting(DetectedFinding::severity).containsExactly("HIGH", "LOW", "MEDIUM", "MEDIUM");
        assertThat(applied).extracting(DetectedFinding::traceSafety).containsExactly("CLIENT", "SERVER_SET", null, null);
        assertThat(SINKS).doesNotContainKey("kisa-insecure-random");
    }

    /** 서블릿에서 요청값을 패키지까지 쓴 정적 호출·컬렉션·요청 맵/이름 목록을 거쳐 SQL에 붙이는 모양(OWASP Benchmark 형태). */
    private static final String SERVLET = """
            package p;
            import java.util.*;
            import javax.servlet.http.*;
            class Q extends HttpServlet {
                public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
                    String param = request.getHeader("h");
                    param = java.net.URLDecoder.decode(param, "UTF-8");
                    List<String> list = new ArrayList<>();
                    list.add(param);
                    String bar = list.get(0);
                    String sql = "SELECT * FROM U WHERE N='" + bar + "'";
                    java.sql.Statement st = null;
                    st.execute(sql);
                    Map<String, String[]> map = request.getParameterMap();
                    String p2 = map.get("x")[0];
                    st.executeQuery("SELECT " + p2);
                    Enumeration<String> names = request.getHeaderNames();
                    String n = names.nextElement();
                    st.executeUpdate("DELETE " + n);
                    List<String> fixed = new ArrayList<>();
                    fixed.add("a");
                    st.executeQuery("SELECT " + fixed.get(0));
                }
            }
            """;

    @Test
    void 패키지_정적호출과_컬렉션과_요청_맵을_거친_SQL_값을_요청값으로_판정한다() {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/Q.java", SERVLET);
        JavaSourceIndex index = JavaSourceIndex.fromSources(sources);
        assertThat(index.failedFiles()).isEmpty();
        String path = "src/main/java/p/Q.java";
        List<DetectedFinding> detected = List.of(
                finding("kisa-sql-injection-java-concat", path, SERVLET, 13, "st.execute("),
                finding("kisa-sql-injection-java-concat", path, SERVLET, 16, "st.executeQuery("),
                finding("kisa-sql-injection-java-concat", path, SERVLET, 19, "st.executeUpdate("),
                finding("kisa-sql-injection-java-concat", path, SERVLET, 22, "st.executeQuery("));

        Map<Integer, TraceSafety> v = new LinkedHashMap<>();
        new SinkTracer(index, TraceRules.empty(), SINKS).trace(detected).forEach(x -> v.put(x.line(), x.safety()));

        assertThat(v).containsEntry(13, TraceSafety.CLIENT)   // getHeader → URLDecoder.decode → list.add/get
                .containsEntry(16, TraceSafety.CLIENT)        // getParameterMap().get(..)[0]
                .containsEntry(19, TraceSafety.CLIENT)        // getHeaderNames().nextElement()
                .containsEntry(22, TraceSafety.SERVER_SET);   // 상수만 넣은 리스트
    }

    /** 상수 조건 함정 — 요청값이 들어가는 갈래가 실제로는 실행되지 않는다(OWASP Benchmark 오탐 유도 형태). 위 4개는 안전, 아래 4개는 취약. */
    private static final String CONSTANT_TRICKS = """
            package p;
            import java.util.*;
            import javax.servlet.http.*;
            class K extends HttpServlet {
                public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
                    String param = request.getParameter("p");
                    java.sql.Statement st = null;
                    int num = 106;
                    String a = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
                    st.execute("A" + a);
                    String b;
                    if ((500 / 42) + num > 200) b = param; else b = "safe";
                    st.execute("B" + b);
                    String guess = "ABC";
                    char target = guess.charAt(1);
                    String c;
                    switch (target) {
                        case 'A': c = param; break;
                        case 'B': c = "bob"; break;
                        case 'C': case 'D': c = param; break;
                        default: c = "x"; break;
                    }
                    st.execute("C" + c);
                    List<String> list = new ArrayList<>();
                    list.add("safe");
                    list.add(param);
                    list.add("moresafe");
                    list.remove(0);
                    String d = list.get(1);
                    st.execute("D" + d);
                    String e = (7 * 42) - num > 200 ? "x" : param;
                    st.execute("E" + e);
                    char target2 = guess.charAt(2);
                    String f;
                    switch (target2) {
                        case 'A': f = param; break;
                        case 'B': f = "bob"; break;
                        case 'C': case 'D': f = param; break;
                        default: f = "x"; break;
                    }
                    st.execute("F" + f);
                    String g = list.get(0);
                    st.execute("G" + g);
                    String h = "safe!";
                    h = param;
                    st.execute("H" + h);
                    h = "fixed";
                    st.execute("I" + h);
                }
            }
            """;

    @Test
    void 상수_조건으로_실행되지_않는_갈래의_값은_출처에서_뺀다() {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/K.java", CONSTANT_TRICKS);
        JavaSourceIndex index = JavaSourceIndex.fromSources(sources);
        assertThat(index.failedFiles()).isEmpty();
        List<DetectedFinding> detected = List.of(10, 13, 23, 30, 32, 41, 43, 46, 48).stream()
                .map(line -> finding("kisa-sql-injection-java-concat", "src/main/java/p/K.java", CONSTANT_TRICKS, line, "st.execute(")).toList();

        Map<Integer, SinkTracer.SinkVerdict> v = new LinkedHashMap<>();
        new SinkTracer(index, TraceRules.empty(), SINKS).trace(detected).forEach(x -> v.put(x.line(), x));

        assertThat(v.get(10).safety()).isEqualTo(TraceSafety.SERVER_SET);   // 삼항: 조건이 항상 참
        assertThat(v.get(13).safety()).isEqualTo(TraceSafety.SERVER_SET);   // if: 조건이 항상 거짓
        assertThat(v.get(23).safety()).isEqualTo(TraceSafety.SERVER_SET);   // switch: 항상 'B'
        assertThat(v.get(30).safety()).isEqualTo(TraceSafety.SERVER_SET);   // remove(0) 뒤 get(1) = "moresafe"
        assertThat(v.get(32).safety()).isEqualTo(TraceSafety.CLIENT);       // 삼항: 조건이 항상 거짓
        assertThat(v.get(41).safety()).isEqualTo(TraceSafety.CLIENT);       // switch: 항상 'C' → fall-through로 param
        assertThat(v.get(43).safety()).isEqualTo(TraceSafety.CLIENT);       // remove(0) 뒤 get(0) = param
        assertThat(v.get(46).safety()).isEqualTo(TraceSafety.CLIENT);       // 앞 값 "safe!"를 param이 덮음
        assertThat(v.get(48).safety()).isEqualTo(TraceSafety.SERVER_SET);   // 쓰기 직전에 "fixed"로 덮음
    }

    @Test
    void 같은_이름의_내부_클래스가_여러_파일에_있으면_같은_파일의_것만_따라간다() {
        String safe = """
                package p;
                import javax.servlet.http.*;
                class T1 extends HttpServlet {
                    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
                        String bar = new Test().doSomething(request.getParameter("p"));
                        java.sql.Statement st = null;
                        st.execute("A" + bar);
                    }
                    private class Test {
                        String doSomething(String param) { return "safe"; }
                    }
                }
                """;
        String vulnerable = """
                package p;
                class T2 {
                    private class Test {
                        String doSomething(String param) { return param; }
                    }
                }
                """;
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/T1.java", safe);
        sources.put("src/main/java/p/T2.java", vulnerable);
        JavaSourceIndex index = JavaSourceIndex.fromSources(sources);

        List<SinkTracer.SinkVerdict> v = new SinkTracer(index, TraceRules.empty(), SINKS)
                .trace(List.of(finding("kisa-sql-injection-java-concat", "src/main/java/p/T1.java", safe, 7, "st.execute(")));

        assertThat(v).singleElement().extracting(SinkTracer.SinkVerdict::safety).isEqualTo(TraceSafety.SERVER_SET);
    }

    /**
     * OWASP Benchmark 함정 모양 — 이름은 요청값 같지만 상수를 돌려주는 헬퍼(getTheValue)를 문자열 메서드(getBytes)로 바꿔 SQL에 붙이고,
     * 명령은 this.getClass().getClassLoader()로 찾은 클래스패스 파일. 예전엔 getBytes()·getClassLoader()를 "외부 메서드"로 보고 판정 불가였다.
     */
    @Test
    void 문자열_메서드와_JVM_클래스_정보도_출처를_따라간다() {
        String helper = """
                package p;
                public class SeparateRequest {
                    private HttpServletRequest request;
                    public SeparateRequest(HttpServletRequest request) { this.request = request; }
                    public String getTheValue(String p) { return "bar"; }
                    public String getTheParameter(String p) { return request.getParameter(p); }
                }
                """;
        String servlet = """
                package p;
                public class Trap extends HttpServlet {
                    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
                        SeparateRequest scr = new SeparateRequest(request);
                        String safe = new String(Base64.decodeBase64(Base64.encodeBase64(scr.getTheValue("x").getBytes())));
                        statement.execute("SELECT * FROM U WHERE P='" + safe + "'");
                        String bad = new String(scr.getTheParameter("x").getBytes());
                        statement.execute("SELECT * FROM U WHERE P='" + bad + "'");
                        java.net.URL url = this.getClass().getClassLoader().getResource("cmd.sh");
                        String cmd = new java.io.File(url.toURI().getPath()).getAbsolutePath();
                        Runtime.getRuntime().exec(cmd);
                    }
                }
                """;
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/SeparateRequest.java", helper);
        sources.put("src/main/java/p/Trap.java", servlet);
        String path = "src/main/java/p/Trap.java";

        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(JavaSourceIndex.fromSources(sources), TraceRules.empty(), SINKS).trace(List.of(
                finding("kisa-sql-injection-java-concat", path, servlet, 6, "statement.execute("),
                finding("kisa-sql-injection-java-concat", path, servlet, 8, "statement.execute("),
                finding("kisa-os-command-exec", path, servlet, 11, "Runtime.getRuntime().exec(")));

        assertThat(verdicts).extracting(SinkTracer.SinkVerdict::safety)
                .containsExactly(TraceSafety.SERVER_SET, TraceSafety.CLIENT, TraceSafety.SERVER_SET);
    }

    /** OWASP Benchmark cmdi(BenchmarkTest00007) 모양 — 명령은 상수 배열, 환경 변수 배열에 요청 헤더. 예전엔 배열 초기화를 몰라 판정 불가였다. */
    @Test
    void 배열로_넘긴_명령_인자도_원소의_출처로_판정한다() {
        String servlet = """
                package p;
                public class CmdServlet extends HttpServlet {
                    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
                        String param = request.getHeader("X-Env");
                        String[] args = {"ls"};
                        String[] argsEnv = {param};
                        Runtime.getRuntime().exec(args, argsEnv);
                        String[] fixed = new String[] {"ping", "localhost"};
                        Runtime.getRuntime().exec(fixed);
                        String[] later = new String[2];
                        later[0] = "echo";
                        later[1] = request.getParameter("msg");
                        Runtime.getRuntime().exec(later);
                    }
                }
                """;
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/CmdServlet.java", servlet);
        String path = "src/main/java/p/CmdServlet.java";

        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(JavaSourceIndex.fromSources(sources), TraceRules.empty(), SINKS).trace(
                List.of(7, 9, 13).stream().map(line -> finding("kisa-os-command-exec", path, servlet, line, "Runtime.getRuntime().exec(")).toList());

        assertThat(verdicts).extracting(SinkTracer.SinkVerdict::safety)
                .containsExactly(TraceSafety.CLIENT, TraceSafety.SERVER_SET, TraceSafety.CLIENT);
    }

    /** 규칙은 패키지까지 쓴 클래스(java.nio.file.Paths)도 잡는다 — 추적도 그 호출을 찾아야 판정이 빠지지 않는다. */
    @Test
    void 패키지까지_쓴_파일_호출도_찾아_판정한다() {
        String servlet = """
                package p;
                public class DownServlet extends HttpServlet {
                    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
                        response.setHeader("Content-Disposition", "attachment");
                        String name = request.getParameter("name");
                        java.nio.file.Path p = java.nio.file.Paths.get(name);
                        java.io.InputStream in = java.nio.file.Files.newInputStream(java.nio.file.Path.of("/static/logo.png"));
                    }
                }
                """;
        String path = "src/main/java/p/DownServlet.java";

        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(JavaSourceIndex.fromSources(Map.of(path, servlet)), TraceRules.empty(), SINKS).trace(List.of(
                finding("kisa-path-traversal-download", path, servlet, 6, "java.nio.file.Paths.get("),
                finding("kisa-path-traversal-download", path, servlet, 7, "java.nio.file.Files.newInputStream(")));

        assertThat(verdicts).extracting(SinkTracer.SinkVerdict::safety).containsExactly(TraceSafety.CLIENT, TraceSafety.SERVER_SET);
    }

    /**
     * OWASP Benchmark 경로 조작(BenchmarkTest00040) 모양 — 요청값을 다른 클래스의 헬퍼가 읽어 Semgrep taint는 놓친다.
     * 실행 지점 규칙(kisa-path-traversal-dynamic-path)이 잡고, 연계 추적은 메서드 이름이 아니라 본문을 따라간다.
     */
    @Test
    void 헬퍼가_읽은_요청값으로_연_파일도_본문을_따라가_판정한다() {
        String helper = """
                package p;
                public class SeparateRequest {
                    private HttpServletRequest request;
                    public SeparateRequest(HttpServletRequest request) { this.request = request; }
                    public String getTheValue(String p) { return "bar"; }
                    public String getTheParameter(String p) { return request.getParameter(p); }
                }
                """;
        String servlet = """
                package p;
                public class FileServlet extends HttpServlet {
                    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
                        SeparateRequest scr = new SeparateRequest(request);
                        java.io.File bad = new java.io.File(scr.getTheParameter("f"));
                        java.io.File safe = new java.io.File("/testfiles/", scr.getTheValue("f"));
                        java.io.FileInputStream in = new java.io.FileInputStream(new java.io.File(scr.getTheParameter("g")));
                    }
                }
                """;
        String path = "src/main/java/p/FileServlet.java";
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/SeparateRequest.java", helper);
        sources.put(path, servlet);

        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(JavaSourceIndex.fromSources(sources), TraceRules.empty(), SINKS).trace(List.of(
                finding("kisa-path-traversal-dynamic-path", path, servlet, 5, "new java.io.File("),
                finding("kisa-path-traversal-dynamic-path", path, servlet, 6, "new java.io.File("),
                finding("kisa-path-traversal-dynamic-path", path, servlet, 7, "new java.io.FileInputStream(")));

        assertThat(verdicts).extracting(SinkTracer.SinkVerdict::safety)
                .containsExactly(TraceSafety.CLIENT, TraceSafety.SERVER_SET, TraceSafety.CLIENT);
        assertThat(verdicts.get(0).evidence()).anyMatch(e -> e.contains("SeparateRequest.java"));
    }

    /** Semgrep 열은 바이트 기준이다 — 앞에 한글이 있으면 글자 열과 다르다. UTF-8·MS949 파일 모두 같은 식을 찾아야 한다. */
    @Test
    void 한글이_앞에_있어도_바이트_열로_범위의_식을_찾는다() {
        String servlet = "package p;\n"
                + "public class Korean extends HttpServlet {\n"
                + "    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {\n"
                + "\t\tString 경로 = request.getParameter(\"p\"); java.io.File f = new java.io.File(경로);\n"
                + "    }\n"
                + "}\n";
        String path = "src/main/java/p/Korean.java";
        JavaSourceIndex index = JavaSourceIndex.fromSources(Map.of(path, servlet));

        for (Charset charset : List.of(StandardCharsets.UTF_8, Charset.forName("MS949"))) {
            DetectedFinding f = finding("kisa-path-traversal-dynamic-path", path, servlet, 4, "new java.io.File(", charset);
            assertThat(new SinkTracer(index, TraceRules.empty(), SINKS).trace(List.of(f)))
                    .singleElement().extracting(SinkTracer.SinkVerdict::safety).isEqualTo(TraceSafety.CLIENT);
        }
    }

    private static Map<String, SinkTracer.SinkVerdict> trace(DetectedFinding... findings) {
        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(index(), TraceRules.empty(), SINKS).trace(List.of(findings));
        Map<String, SinkTracer.SinkVerdict> byKey = new LinkedHashMap<>();
        verdicts.forEach(v -> byKey.put(v.ruleId() + ":" + v.line(), v));
        assertThat(byKey.keySet()).hasSize(Set.of(findings).size());
        return byKey;
    }

    private static JavaSourceIndex index() {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/java/p/C.java", CONTROLLER);
        sources.put("src/main/java/p/S.java", SERVICE);
        JavaSourceIndex index = JavaSourceIndex.fromSources(sources);
        assertThat(index.failedFiles()).isEmpty();
        return index;
    }

    /** SERVICE(S.java)의 탐지. */
    private static DetectedFinding finding(String ruleId, int line, String sinkStart) {
        return finding(ruleId, "src/main/java/p/S.java", SERVICE, line, sinkStart);
    }

    private static DetectedFinding finding(String ruleId, String path, String source, int line, String sinkStart) {
        return finding(ruleId, path, source, line, sinkStart, StandardCharsets.UTF_8);
    }

    /**
     * Semgrep이 주는 것처럼 범위(열)를 붙인 탐지 — 그 줄에서 sinkStart(호출 시작, "(" 로 끝남)부터 짝이 맞는 ")"까지.
     * 열은 Semgrep처럼 파일 인코딩의 바이트 기준이고 끝 열은 끝 글자 다음이다.
     */
    private static DetectedFinding finding(String ruleId, String path, String source, int line, String sinkStart, Charset charset) {
        String text = source.split("\n", -1)[line - 1];
        int begin = text.indexOf(sinkStart);
        assertThat(begin).as("%d번째 줄에 %s가 없다", line, sinkStart).isNotNegative();
        int end = closingParen(text, begin + sinkStart.length() - 1) + 1;
        int startCol = text.substring(0, begin).getBytes(charset).length + 1;
        int endCol = text.substring(0, end).getBytes(charset).length + 1;
        return new DetectedFinding(ruleId + ":" + line, ruleId, "분류", "항목", "CWE-1", "MEDIUM", path,
                line, line, "메시지", "code", line, null, null, null, null).withColumns(startCol, endCol);
    }

    /** open 위치의 "("와 짝이 맞는 ")" 위치(문자열 안 괄호는 건너뛴다). */
    private static int closingParen(String text, int open) {
        int depth = 0;
        boolean inString = false;
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inString) {
                if (c == '\\') i++;
                else if (c == '"') inString = false;
            } else if (c == '"') {
                inString = true;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return i;
            }
        }
        throw new IllegalArgumentException("괄호 짝이 없다: " + text);
    }

    private static Map<String, TraceSink> loadSinks() {
        try {
            return new RuleSetLoader().load(Path.of("../securecode/rules")).sinks();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
