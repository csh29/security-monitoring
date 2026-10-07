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
