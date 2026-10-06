import javax.servlet.http.*;

@Controller
class OpenRedirectTest {

    @GetMapping("/login/done")
    public String done(@RequestParam String returnUrl) {
        // ruleid: kisa-open-redirect-request
        return "redirect:" + returnUrl;
    }

    void servlet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        // ruleid: kisa-open-redirect-request
        response.sendRedirect(next);
    }

    @GetMapping("/go")
    public ModelAndView go(@RequestParam("url") String url) {
        // ruleid: kisa-open-redirect-request
        return new ModelAndView(new RedirectView(url));
    }

    private static final String GATEWAY = "https://gw.example.com";

    @GetMapping("/loading")
    public ModelAndView loading(@RequestParam("data") String data) {
        String uri = GATEWAY + "/kakao/loading.html?data=" + data;
        // ok: kisa-open-redirect-request
        return new ModelAndView("redirect:" + uri);
    }

    @GetMapping("/path")
    public String path(@RequestParam String next) {
        // "/" + "/evil.com" → "//evil.com" (프로토콜 상대 주소 — 외부로 나간다)
        String target = "/" + next;
        // ruleid: kisa-open-redirect-request
        return "redirect:" + target;
    }

    @GetMapping("/host")
    public ModelAndView host(@RequestParam String next) {
        String uri = GATEWAY + next;
        // ruleid: kisa-open-redirect-request
        return new ModelAndView("redirect:" + uri);
    }

    @GetMapping("/home")
    public String home(@RequestParam String tab) {
        // ok: kisa-open-redirect-request
        return "redirect:/main";
    }

    void fixed(HttpServletResponse response) throws Exception {
        // ok: kisa-open-redirect-request
        response.sendRedirect("/login");
    }
}
