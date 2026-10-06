import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

class SsrfTest {
    private RestTemplate restTemplate;

    void fromRequest(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        // ruleid: kisa-ssrf-request, kisa-ssrf-dynamic-url
        URL url = new URL(target);
        // ruleid: kisa-ssrf-request, kisa-ssrf-dynamic-url
        restTemplate.getForObject(target, String.class);
    }

    @GetMapping("/proxy")
    void fromSpring(@RequestParam("url") String target, @RequestBody java.util.Map<String, Object> param) throws Exception {
        // ruleid: kisa-ssrf-request, kisa-ssrf-dynamic-url
        new URL(target);
        // ruleid: kisa-ssrf-request, kisa-ssrf-dynamic-url
        restTemplate.getForObject((String) param.get("callbackUrl"), String.class);
    }

    private static final String API_BASE = "https://api.example.com";

    @GetMapping("/items")
    void fixedHost(@RequestParam String q) throws Exception {
        // ok: kisa-ssrf-request, kisa-ssrf-dynamic-url
        new URL("https://api.example.com/v1/items?q=" + q);
        // ok: kisa-ssrf-request, kisa-ssrf-dynamic-url
        restTemplate.getForObject(API_BASE + "/v1/items?q=" + q, String.class);
        // ruleid: kisa-ssrf-request, kisa-ssrf-dynamic-url
        restTemplate.getForObject(API_BASE + q, String.class);
    }

    void variable(String endpoint) throws Exception {
        // ruleid: kisa-ssrf-dynamic-url
        restTemplate.postForObject(endpoint, null, String.class);
    }

    void constants() throws Exception {
        // ok: kisa-ssrf-dynamic-url
        URL url = new URL("https://api.example.com/v1");
        // ok: kisa-ssrf-dynamic-url
        restTemplate.getForObject("https://api.example.com/v1", String.class);
    }
}
