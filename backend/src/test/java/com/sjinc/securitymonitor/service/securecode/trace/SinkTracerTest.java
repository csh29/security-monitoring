package com.sjinc.securitymonitor.service.securecode.trace;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;

class SinkTracerTest {

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
                finding("kisa-ssrf-dynamic-url", 14),     // fetch: 요청값 url
                finding("kisa-ssrf-dynamic-url", 17),     // callBatch: @Value 설정값
                finding("kisa-ssrf-dynamic-url", 21),     // items: 고정 호스트 + 쿼리
                finding("kisa-file-upload-save", 24),     // save: 원래 파일명
                finding("kisa-file-upload-save", 27),     // saveSafe: UUID
                finding("kisa-os-command-exec", 31));     // ping: 상수 명령

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
        List<DetectedFinding> detected = List.of(
                finding("kisa-ssrf-dynamic-url", 14), finding("kisa-ssrf-dynamic-url", 17),
                finding("kisa-ssrf-dynamic-url", 99), finding("kisa-insecure-random", 14));

        List<DetectedFinding> applied = SinkTracer.apply(detected, new SinkTracer(index(), TraceRules.empty()).trace(detected));

        assertThat(applied).extracting(DetectedFinding::severity).containsExactly("HIGH", "LOW", "MEDIUM", "MEDIUM");
        assertThat(applied).extracting(DetectedFinding::traceSafety).containsExactly("CLIENT", "SERVER_SET", null, null);
        assertThat(applied).extracting(DetectedFinding::fingerprint).containsExactly("fp14", "fp17", "fp99", "fp14");
        assertThat(SinkTracer.supports("kisa-insecure-random")).isFalse();
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
        List<DetectedFinding> detected = List.of(13, 16, 19, 22).stream()
                .map(line -> finding("kisa-sql-injection-java-concat", line, "src/main/java/p/Q.java")).toList();

        Map<Integer, TraceSafety> v = new LinkedHashMap<>();
        new SinkTracer(index, TraceRules.empty()).trace(detected).forEach(x -> v.put(x.line(), x.safety()));

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
                .map(line -> finding("kisa-sql-injection-java-concat", line, "src/main/java/p/K.java")).toList();

        Map<Integer, SinkTracer.SinkVerdict> v = new LinkedHashMap<>();
        new SinkTracer(index, TraceRules.empty()).trace(detected).forEach(x -> v.put(x.line(), x));

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

        List<SinkTracer.SinkVerdict> v = new SinkTracer(index, TraceRules.empty())
                .trace(List.of(finding("kisa-sql-injection-java-concat", 7, "src/main/java/p/T1.java")));

        assertThat(v).singleElement().extracting(SinkTracer.SinkVerdict::safety).isEqualTo(TraceSafety.SERVER_SET);
    }

    private static Map<String, SinkTracer.SinkVerdict> trace(DetectedFinding... findings) {
        List<SinkTracer.SinkVerdict> verdicts = new SinkTracer(index(), TraceRules.empty()).trace(List.of(findings));
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

    private static DetectedFinding finding(String ruleId, int line) {
        return finding(ruleId, line, "src/main/java/p/S.java");
    }

    private static DetectedFinding finding(String ruleId, int line, String path) {
        return new DetectedFinding("fp" + line, ruleId, "분류", "항목", "CWE-1", "MEDIUM", path,
                line, line, "메시지", "code", line, null, null, null, null);
    }
}
