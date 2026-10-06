import java.net.InetAddress;
import javax.servlet.http.HttpServletRequest;

class ApiMisuseTest {
    boolean trusted(HttpServletRequest request) throws Exception {
        InetAddress addr = InetAddress.getByName(request.getRemoteAddr());
        // ruleid: kisa-dns-lookup-security-decision
        if (addr.getCanonicalHostName().endsWith(".sjinc.co.kr")) {
            return true;
        }
        // ruleid: kisa-dns-lookup-security-decision
        return "admin.sjinc.co.kr".equals(request.getRemoteHost());
    }

    String log(InetAddress addr, HttpServletRequest request) {
        // ok: kisa-dns-lookup-security-decision
        String host = addr.getCanonicalHostName();
        // ok: kisa-dns-lookup-security-decision
        return request.getRemoteAddr().equals("10.0.0.1") ? host : "";
    }
}
