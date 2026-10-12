package com.sjinc.securitymonitor.service.securecode.trace;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;

class AuthCoverageTest {

    /** Java 설정으로 인터셉터를 /**에 걸고 로그인·공개 경로를 뺀다. 인터셉터는 세션에 로그인 정보가 없으면 false. */
    private static Map<String, String> springBootApp() {
        Map<String, String> sources = new TreeMap<>();
        sources.put("src/main/java/p/WebConfig.java", """
                package p;
                public class WebConfig implements WebMvcConfigurer {
                    private static final String[] PUBLIC = {"/public/**", "/health"};
                    private final AuthInterceptor authInterceptor;
                    public void addInterceptors(InterceptorRegistry registry) {
                        registry.addInterceptor(authInterceptor)
                                .addPathPatterns("/**")
                                .excludePathPatterns("/login", "/loginProcess")
                                .excludePathPatterns(PUBLIC);
                        registry.addInterceptor(new LogInterceptor());
                    }
                }
                """);
        sources.put("src/main/java/p/AuthInterceptor.java", """
                package p;
                public class AuthInterceptor implements HandlerInterceptor {
                    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                        // 로그인 정보가 없으면 막는다
                        Object user = request.getSession().getAttribute("LOGIN_USER");
                        if (user == null) {
                            response.sendRedirect("/login");
                            return false;
                        }
                        return true;
                    }
                }
                """);
        sources.put("src/main/java/p/LogInterceptor.java", """
                package p;
                public class LogInterceptor implements HandlerInterceptor {
                    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                        log.info(request.getHeader("User-Agent"));
                        return true;
                    }
                }
                """);
        sources.put("src/main/java/p/CommonController.java", """
                package p;
                @RestController
                @RequestMapping("/common")
                public class CommonController {
                    @PostMapping("/deleteOne")
                    public Object deleteOne() { return null; }
                    @RequestMapping(value = "/list", method = RequestMethod.GET)
                    public Object list() { return null; }
                }
                """);
        sources.put("src/main/java/p/LoginController.java", """
                package p;
                @Controller
                public class LoginController {
                    @PostMapping({"/login", "/loginProcess"})
                    public Object login() { return null; }
                    @GetMapping("/public/notice")
                    public Object notice() { return null; }
                }
                """);
        return sources;
    }

    @Test
    void Java_설정의_인터셉터_등록과_적용_제외_경로를_읽는다() {
        Map<String, String> sources = springBootApp();
        List<AuthCoverage.Hook> hooks = AuthCoverage.hooks(sources, JavaSourceIndex.fromSources(sources));

        assertThat(hooks).extracting(AuthCoverage.Hook::className).containsExactly("AuthInterceptor", "LogInterceptor");
        AuthCoverage.Hook auth = hooks.get(0);
        assertThat(auth.include()).containsExactly("/**");
        assertThat(auth.exclude()).containsExactly("/login", "/loginProcess", "/public/**", "/health"); // 상수 배열까지 읽는다
        assertThat(auth.patternsKnown()).isTrue();
        assertThat(hooks.get(1).include()).containsExactly("/**");          // addPathPatterns가 없으면 전체
    }

    @Test
    void 로그인_정보를_읽고_없으면_막는_장치만_후보다() {
        Map<String, String> sources = springBootApp();
        JavaSourceIndex java = JavaSourceIndex.fromSources(sources);

        List<AuthCoverage.Candidate> candidates = AuthCoverage.candidates(AuthCoverage.hooks(sources, java), sources, java);

        // LogInterceptor는 헤더를 읽지만 막지 않는다.
        assertThat(candidates).extracting(AuthCoverage.Candidate::className).containsExactly("AuthInterceptor");
        assertThat(candidates.get(0).evidence())
                .anyMatch(e -> e.startsWith("로그인 정보 읽기: AuthInterceptor.java:5 ") && e.contains("getSession()"))
                .anyMatch(e -> e.startsWith("없으면 막기: AuthInterceptor.java:7 ") && e.contains("sendRedirect"))
                .anyMatch(e -> e.contains("제외 [/login, /loginProcess, /public/**, /health]"));
    }

    @Test
    void 인정된_장치가_적용되지_않는_요청_처리_메서드만_낸다() {
        Map<String, String> sources = springBootApp();
        JavaSourceIndex java = JavaSourceIndex.fromSources(sources);

        AuthCoverage.Result result = AuthCoverage.judge(sources, java, Set.of("AuthInterceptor"));

        assertThat(result.judged()).isTrue();
        assertThat(result.endpoints()).isEqualTo(4);
        assertThat(result.unprotected()).extracting(u -> u.endpoint().handler())
                .containsExactlyInAnyOrder("LoginController.login()", "LoginController.notice()");
        AuthCoverage.Unprotected login = result.unprotected().stream()
                .filter(u -> u.endpoint().handler().equals("LoginController.login()")).findFirst().orElseThrow();
        assertThat(login.endpoint().paths()).containsExactly("/login", "/loginProcess");
        assertThat(login.endpoint().line()).isEqualTo(4);
        assertThat(login.reasons()).allMatch(r -> r.contains("AuthInterceptor 제외 경로"));
        // 클래스 경로 + 메서드 경로, RequestMapping의 method
        List<AuthCoverage.Endpoint> endpoints = AuthCoverage.endpoints(java, new ArrayList<>());
        assertThat(endpoints).anyMatch(e -> e.paths().equals(List.of("/common/list")) && e.httpMethod().equals("GET"));
    }

    @Test
    void 장치를_인정하지_않았거나_찾지_못하면_판정하지_않는다() {
        Map<String, String> sources = springBootApp();
        JavaSourceIndex java = JavaSourceIndex.fromSources(sources);

        assertThat(AuthCoverage.judge(sources, java, Set.of()).judged()).isFalse();
        AuthCoverage.Result missing = AuthCoverage.judge(sources, java, Set.of("SsoFilter"));
        assertThat(missing.judged()).isFalse();
        assertThat(missing.notes()).anyMatch(n -> n.contains("SsoFilter"));
    }

    @Test
    void 경로를_상수로_못_읽으면_판정하지_않는다() {
        Map<String, String> sources = new TreeMap<>(springBootApp());
        sources.put("src/main/java/p/WebConfig.java", """
                package p;
                public class WebConfig implements WebMvcConfigurer {
                    public void addInterceptors(InterceptorRegistry registry) {
                        registry.addInterceptor(new AuthInterceptor()).excludePathPatterns(props.getPublicPaths());
                    }
                }
                """);
        JavaSourceIndex java = JavaSourceIndex.fromSources(sources);

        AuthCoverage.Result result = AuthCoverage.judge(sources, java, Set.of("AuthInterceptor"));

        assertThat(result.judged()).isFalse();
        assertThat(result.notes()).anyMatch(n -> n.contains("상수로 읽지 못해"));
    }

    @Test
    void XML_인터셉터와_web_xml_필터를_읽고_필터는_서블릿_패턴으로_맞춘다() {
        Map<String, String> sources = new TreeMap<>();
        sources.put("src/main/webapp/WEB-INF/dispatcher-servlet.xml", """
                <beans>
                  <bean id="sessionCheck" class="kr.co.x.SessionCheckInterceptor"/>
                  <mvc:interceptors>
                    <bean class="kr.co.x.LocaleInterceptor"/>
                    <mvc:interceptor>
                      <mvc:mapping path="/**"/>
                      <!-- <mvc:exclude-mapping path="/commented/**"/> -->
                      <mvc:exclude-mapping path="/login.do"/>
                      <ref bean="sessionCheck"/>
                    </mvc:interceptor>
                  </mvc:interceptors>
                </beans>
                """);
        sources.put("src/main/webapp/WEB-INF/web.xml", """
                <web-app>
                  <filter><filter-name>auth</filter-name><filter-class>kr.co.x.AuthFilter</filter-class></filter>
                  <filter-mapping><filter-name>auth</filter-name><url-pattern>/api/*</url-pattern></filter-mapping>
                </web-app>
                """);
        JavaSourceIndex java = JavaSourceIndex.fromSources(sources);

        List<AuthCoverage.Hook> hooks = AuthCoverage.hooks(sources, java);

        assertThat(hooks).extracting(AuthCoverage.Hook::className)
                .containsExactlyInAnyOrder("SessionCheckInterceptor", "LocaleInterceptor", "AuthFilter");
        AuthCoverage.Hook session = hooks.stream().filter(h -> h.className().equals("SessionCheckInterceptor")).findFirst().orElseThrow();
        assertThat(session.exclude()).containsExactly("/login.do");  // 주석 안의 제외 경로는 뺀다
        AuthCoverage.Hook filter = hooks.stream().filter(h -> h.className().equals("AuthFilter")).findFirst().orElseThrow();
        assertThat(filter.covers("/api/users")).isTrue();
        assertThat(filter.covers("/api")).isTrue();
        assertThat(filter.covers("/apix/users")).isFalse();
        assertThat(AuthCoverage.matches(AuthCoverage.Kind.FILTER, "*.do", "/a/b.do")).isTrue();
    }
}
