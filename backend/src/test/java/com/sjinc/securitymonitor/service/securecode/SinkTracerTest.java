package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

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
        return new DetectedFinding("fp" + line, ruleId, "분류", "항목", "CWE-1", "MEDIUM", "src/main/java/p/S.java",
                line, line, "메시지", "code", line, null, null);
    }
}
