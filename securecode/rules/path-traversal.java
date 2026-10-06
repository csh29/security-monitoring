import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import org.apache.commons.io.FilenameUtils;

@RestController
class PathTraversalTest {

    @GetMapping("/download")
    void download(@RequestParam String file, HttpServletResponse response) throws Exception {
        // ruleid: kisa-path-traversal-request
        File target = new File("/data/upload/" + file);
        // ruleid: kisa-path-traversal-request
        Path p = Paths.get("/data", file);
    }

    @GetMapping("/view/{name}")
    void view(@PathVariable("name") String name) throws Exception {
        // ruleid: kisa-path-traversal-request
        FileInputStream in = new FileInputStream(name);
    }

    @PostMapping("/download2")
    void downloadByBody(@RequestBody java.util.Map<String, Object> param) throws Exception {
        // ruleid: kisa-path-traversal-request
        File target = new File("/data/upload/" + param.get("filePath"));
    }

    void servlet(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        // ruleid: kisa-path-traversal-request
        new FileReader(path);
    }

    @GetMapping("/safe")
    void safe(@RequestParam String file, @RequestParam Long id) throws Exception {
        // ok: kisa-path-traversal-request
        File target = new File("/data/upload/" + FilenameUtils.getName(file));
        String storedName = "2026/10/uuid.pdf";
        // ok: kisa-path-traversal-request
        File byId = new File("/data/upload/" + storedName);
        // ok: kisa-path-traversal-request
        File fixed = new File("/data/upload/notice.pdf");
    }

    private String lookupStoredName(Long id) {
        return "a.pdf";
    }

    void downloadBySavedPath(String savedPath, HttpServletResponse response) throws Exception {
        response.setHeader("Content-Disposition", "attachment; filename=a.pdf");
        // ruleid: kisa-path-traversal-download
        InputStream in = new FileInputStream(savedPath);
        // ok: kisa-path-traversal-download
        InputStream logo = new FileInputStream("/static/logo.png");
    }

    void notDownload(String path) throws Exception {
        // ok: kisa-path-traversal-download
        InputStream in = new FileInputStream(path);
    }
}
