import javax.servlet.http.HttpServletRequest;

class CommandInjectionTest {
    void fromRequest(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ruleid: kisa-os-command-injection-request, kisa-os-command-exec
        Runtime.getRuntime().exec("ping " + host);
        String file = request.getParameter("file");
        // ruleid: kisa-os-command-injection-request, kisa-os-command-exec
        new ProcessBuilder("sh", "-c", "cat " + file).start();
    }

    @PostMapping("/ping")
    void fromSpring(@RequestParam String host, @RequestBody java.util.Map<String, Object> param) throws Exception {
        // ruleid: kisa-os-command-injection-request, kisa-os-command-exec
        Runtime.getRuntime().exec("ping " + host);
        // ruleid: kisa-os-command-injection-request, kisa-os-command-exec
        new ProcessBuilder("sh", "-c", "cat " + param.get("file")).start();
    }

    void variable(String cmd, java.util.List<String> args) throws Exception {
        // ruleid: kisa-os-command-exec
        Runtime.getRuntime().exec(cmd);
        // ruleid: kisa-os-command-exec
        new ProcessBuilder(args).start();
    }

    void constants() throws Exception {
        // ok: kisa-os-command-exec
        Runtime.getRuntime().exec("hostname");
        // ok: kisa-os-command-exec
        new ProcessBuilder("git", "status").start();
    }
}
