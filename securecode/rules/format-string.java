import java.io.PrintWriter;
import java.text.MessageFormat;
import java.util.Locale;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

class FormatStringTest {

    void servlet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fmt = request.getParameter("fmt");
        // ruleid: kisa-format-string-request
        String a = String.format(fmt, "x");
        // ruleid: kisa-format-string-request
        String b = String.format(Locale.KOREA, fmt, "x");
        PrintWriter out = response.getWriter();
        // ruleid: kisa-format-string-request
        out.printf(fmt, 1);
        // ruleid: kisa-format-string-request
        String c = MessageFormat.format(fmt, "x");
        // ok: kisa-format-string-request
        String d = String.format("이름: %s", fmt);
        // ok: kisa-format-string-request
        String e = MessageFormat.format("이름: {0}", fmt);
        // ok: kisa-format-string-request
        String g = String.format("%s %s", fmt, "x");
    }

    @GetMapping("/f")
    String spring(@RequestParam("m") String message) {
        // ruleid: kisa-format-string-request
        return java.lang.String.format(message);
    }

    String constant() {
        String fmt = "%d건";
        // ok: kisa-format-string-request
        return String.format(fmt, 3);
    }
}
