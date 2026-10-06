import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.web.bind.annotation.*;

class SecurityConfig {
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // ruleid: kisa-csrf-disabled
        http.csrf(AbstractHttpConfigurer::disable)
            // ruleid: kisa-authn-permit-all
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll());
        return http.build();
    }
}

class RoleService {
    void approve(Map<String, Object> param, HttpServletRequest request) {
        // ruleid: kisa-authz-client-controlled-role
        String isAdmin = (String) param.get("isAdmin");
        // ruleid: kisa-authz-client-controlled-role
        String role = request.getParameter("role");
        // ok: kisa-authz-client-controlled-role
        String name = (String) param.get("evntNm");
    }

    boolean login(String userId) {
        // ruleid: kisa-authz-hardcoded-account
        if ("admin".equals(userId)) return true;
        // ok: kisa-authz-hardcoded-account
        return "Y".equals(userId);
    }
}

@RestController
class SampleController {
    @PostMapping("/a")
    // ruleid: kisa-authz-missing-user-scope
    public Object noScope(HttpServletRequest request, @RequestBody Map<String, String> param) {
        return service.list(param);
    }

    @AddUserInfo
    @PostMapping("/b")
    // ok: kisa-authz-missing-user-scope
    public Object withScope(HttpServletRequest request, @RequestBody Map<String, String> param) {
        return service.list(param);
    }

    @PostMapping("/c")
    // ok: kisa-authz-missing-user-scope
    public Object readsSession(HttpServletRequest request, @RequestBody Map<String, String> param) {
        LoginUserVo user = (LoginUserVo) request.getSession().getAttribute("LOGIN_USER");
        return service.list(param, user);
    }

    @PostMapping("/d")
    // ok: kisa-authz-missing-user-scope
    public Object manual(HttpServletRequest request, @RequestBody HashMap param) {
        FrameEtcUtil.addUserInfo(param, request);
        return service.list(param);
    }

    @GetMapping("/e")
    // ok: kisa-authz-missing-user-scope
    public Object noBody() {
        return "ok";
    }
}
