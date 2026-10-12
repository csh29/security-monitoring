import javax.servlet.http.*;

class CookieTest {

    void login(HttpServletResponse response, String token) {
        Cookie keep = new Cookie("AUTH", token);
        // ruleid: kisa-persistent-cookie
        keep.setMaxAge(60 * 60 * 24 * 30);
        response.addCookie(keep);

        Cookie remove = new Cookie("AUTH", "");
        // ok: kisa-persistent-cookie
        remove.setMaxAge(0);

        Cookie session = new Cookie("LANG", "ko");
        // ok: kisa-persistent-cookie
        session.setMaxAge(-1);
    }

    void jakarta(jakarta.servlet.http.Cookie c, int age) {
        // ruleid: kisa-persistent-cookie
        c.setMaxAge(age);
    }
}
