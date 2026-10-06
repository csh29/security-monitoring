import javax.naming.directory.*;
import javax.script.*;
import javax.servlet.http.*;
import javax.xml.xpath.*;
import org.springframework.expression.ExpressionParser;
import org.springframework.ldap.support.LdapEncoder;

@RestController
class InjectionTest {

    @GetMapping("/user")
    void ldap(@RequestParam String uid, DirContext ctx, SearchControls sc) throws Exception {
        // ruleid: kisa-ldap-injection-request
        ctx.search("ou=people", "(uid=" + uid + ")", sc);
        // ok: kisa-ldap-injection-request
        ctx.search("ou=people", "(uid=" + LdapEncoder.filterEncode(uid) + ")", sc);
    }

    void xpath(HttpServletRequest request, XPath xpath, Object doc) throws Exception {
        String name = request.getParameter("name");
        // ruleid: kisa-xpath-injection-request
        xpath.evaluate("//user[@name='" + name + "']", doc);
        // ok: kisa-xpath-injection-request
        xpath.evaluate("//user[@name=$name]", doc);
    }

    @PostMapping("/calc")
    Object code(@RequestParam("expr") String expr, ScriptEngine engine, ExpressionParser parser) throws Exception {
        // ruleid: kisa-code-injection-request
        engine.eval(expr);
        // ruleid: kisa-code-injection-request
        parser.parseExpression(expr);
        // ok: kisa-code-injection-request
        return parser.parseExpression("1 + 1");
    }

    @GetMapping("/lang")
    void header(@RequestParam String lang, HttpServletResponse response) {
        // ruleid: kisa-http-response-splitting
        response.setHeader("Content-Language", lang);
        // ruleid: kisa-http-response-splitting
        response.addCookie(new Cookie("lang", lang));
        // ok: kisa-http-response-splitting
        response.setHeader("Content-Language", lang.replaceAll("[\\r\\n]", ""));
        // ok: kisa-http-response-splitting
        response.setHeader("X-Frame-Options", "DENY");
    }
}
