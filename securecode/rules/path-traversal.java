import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import org.apache.commons.io.FilenameUtils;

@RestController
class PathTraversalTest {

    private static final String UPLOAD_DIR = "/data/upload";

    @GetMapping("/download")
    void download(@RequestParam String file, HttpServletResponse response) throws Exception {
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        File target = new File("/data/upload/" + file);
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        Path p = Paths.get("/data", file);
    }

    @GetMapping("/view/{name}")
    void view(@PathVariable("name") String name) throws Exception {
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        FileInputStream in = new FileInputStream(name);
    }

    @PostMapping("/download2")
    void downloadByBody(@RequestBody java.util.Map<String, Object> param) throws Exception {
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        File target = new File("/data/upload/" + param.get("filePath"));
    }

    void servlet(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        new FileReader(path);
    }

    @GetMapping("/safe")
    void safe(@RequestParam String file, @RequestParam Long id) throws Exception {
        // ruleid: kisa-path-traversal-dynamic-path
        File target = new File("/data/upload/" + FilenameUtils.getName(file));
        String storedName = "2026/10/uuid.pdf";
        // 지역 상수·static final 상수는 Semgrep이 값을 계산해 문자열 상수로 본다 — 실행 지점 규칙도 뺀다.
        // ok: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        File byId = new File("/data/upload/" + storedName);
        // ok: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        File fixed = new File("/data/upload/notice.pdf");
    }

    private String lookupStoredName(Long id) {
        return "a.pdf";
    }

    void downloadBySavedPath(String savedPath, HttpServletResponse response) throws Exception {
        response.setHeader("Content-Disposition", "attachment; filename=a.pdf");
        // ruleid: kisa-path-traversal-download, kisa-path-traversal-dynamic-path
        InputStream in = new FileInputStream(savedPath);
        // ok: kisa-path-traversal-download, kisa-path-traversal-dynamic-path
        InputStream logo = new FileInputStream("/static/logo.png");
    }

    void notDownload(String path) throws Exception {
        // ruleid: kisa-path-traversal-dynamic-path
        InputStream in = new FileInputStream(path);
    }

    // 패키지까지 쓴 클래스(import 없이) — OWASP Benchmark 모양.
    void qualified(HttpServletRequest request) throws Exception {
        String fileName = "/testfiles/" + request.getParameter("f");
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        java.io.FileOutputStream fos = new java.io.FileOutputStream(new java.io.FileInputStream(fileName).getFD());
        // ruleid: kisa-path-traversal-request, kisa-path-traversal-dynamic-path
        java.nio.file.Path p = java.nio.file.Paths.get(fileName);
    }

    // 요청값을 헬퍼가 읽으면(OWASP Benchmark SeparateClassRequest) taint는 놓친다 — 실행 지점 규칙이 잡고 출처는 연계 추적이 판정한다.
    void viaHelper(HttpServletRequest request) throws Exception {
        org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);
        String param = scr.getTheParameter("f");
        // ruleid: kisa-path-traversal-dynamic-path
        java.io.File fileTarget = new java.io.File(param);
        // ok: kisa-path-traversal-dynamic-path
        InputStream in = new FileInputStream(fileTarget);
        // ok: kisa-path-traversal-dynamic-path
        File child = new File(fileTarget, "a.txt");
        // ok: kisa-path-traversal-dynamic-path
        File config = new File(UPLOAD_DIR);
    }
}
