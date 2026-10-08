import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

class XssJavaTest {
    void bad(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String keyword = request.getParameter("q");
        // ruleid: kisa-xss-servlet-write
        response.getWriter().write("<p>" + keyword + "</p>");
        PrintWriter out = response.getWriter();
        // ruleid: kisa-xss-servlet-write
        out.println(request.getParameter("name"));
    }

    @GetMapping("/search")
    void fromSpring(@RequestParam String q, HttpServletResponse response) throws Exception {
        // ruleid: kisa-xss-servlet-write
        response.getWriter().write("<p>" + q + "</p>");
        // ok: kisa-xss-servlet-write
        response.getWriter().write("<p>" + HtmlUtils.htmlEscape(q) + "</p>");
    }

    void good(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String keyword = HtmlUtils.htmlEscape(request.getParameter("q"));
        // ok: kisa-xss-servlet-write
        response.getWriter().write("<p>" + keyword + "</p>");
        // ok: kisa-xss-servlet-write
        response.getWriter().write("{\"result\":\"ok\"}");
    }

    // 패키지까지 쓴 클래스(import 없이) — OWASP Benchmark 모양. 이스케이프도 패키지까지 쓴 이름으로 인정해야 한다.
    void qualified(jakarta.servlet.http.HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = "/tmp/" + request.getParameter("f");
        // ok: kisa-xss-servlet-write
        response.getWriter().println("Now ready: " + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));
        java.io.PrintWriter out = response.getWriter();
        // ruleid: kisa-xss-servlet-write
        out.println(fileName);
    }
}
