package com.sjinc.securitymonitor.config;

import com.sjinc.securitymonitor.security.CsrfCookieFilter;
import com.sjinc.securitymonitor.security.RequiresProgramAuthorizationManager;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;

/**
 * 폼 로그인 기반 세션 인증 + 추가 프로그램(관리 화면) API 접근 제어 정책.
 *
 * <p>기본 태도는 "허용 목록에 없으면 막는다"(fail closed)다 — {@code anyRequest()}가
 * {@link RequiresProgramAuthorizationManager} 하나로 떨어지고, 그 매니저가 로그인 여부와
 * (컨트롤러에 붙은 {@code @RequiresProgram} 어노테이션이 있다면) 프로그램 권한까지 함께
 * 판단한다. URL 패턴을 여기 나열하지 않으므로, 새 관리 화면 API를 추가할 때 SecurityConfig를
 * 고칠 필요가 없다 — 그 컨트롤러에 {@code @RequiresProgram("app-mng")}처럼 어노테이션만
 * 붙이면 된다(자세한 설명은 그 어노테이션과 매니저의 클래스 주석 참고).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RequiresProgramAuthorizationManager requiresProgramAuthorizationManager;

    /** H2 콘솔을 켰을 때만 그 경로를 CSRF 검증에서 뺀다(아래 csrf 설정 주석 참고). */
    @Value("${spring.h2.console.enabled:false}")
    private boolean h2ConsoleEnabled;

    /** 로그인 없이 열어야 하는 것. */
    private static final String[] PUBLIC_URLS = {
            "/login", "/css/**", "/js/**", "/assets/**", "/favicon.ico",
            "/api/ai/**", // 세션 로그인이 없는 파이썬 AI 배치용 API. 대신 X-Internal-Token 헤더로 자체 인증한다.
            "/error" // 없으면 sendError()로 인한 /error 내부 포워딩까지 인증을 요구해서, 401/404 응답이 로그인 리다이렉트로 바뀌어 버린다.
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .anyRequest().access(requiresProgramAuthorizationManager))
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll())
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll())
                // 로그인 안 된(세션 만료·서버 재기동 포함) /api/** 요청은 로그인 페이지로 302를 보내지 않고
                // 401로 끝낸다. 302를 보내면 화면의 fetch가 리다이렉트를 조용히 따라가 로그인 페이지 HTML을
                // 200으로 받고, 그걸 JSON으로 읽다가 "Unexpected token '<'" 같은 엉뚱한 오류가 난다.
                // 401을 받은 화면은 공통 fetch 래퍼(loading-overlay.html)가 로그인 페이지로 보낸다.
                // 화면(페이지) 요청은 지금처럼 로그인 페이지로 리다이렉트한다.
                .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint()))
                // /api/**도 (바로 아래 /api/ai/** 하나만 빼고) CSRF 검증을 받는다. 쿠키에 담은 토큰 값을 화면 JS가 그대로
                // X-XSRF-TOKEN 헤더로 실어 보내는 방식(CookieCsrfTokenRepository +
                // 일반 CsrfTokenRequestAttributeHandler, BREACH 방지용 XOR 인코딩 없이 원문 비교)
                // — loading-overlay.html이 감싸는 공통 fetch 래퍼가 모든 화면에서 자동으로 붙여준다.
                // 예전엔 /api/**를 통째로 CSRF 검증에서 제외했는데, 그러면 로그인한 관리자가
                // 악성 페이지를 열기만 해도 그 브라우저가 대신 POST /api/scan, /api/users 같은
                // 상태 변경 요청을 쏠 수 있었다.
                .csrf(csrf -> csrf
                        // 단, /api/ai/**는 제외한다. CSRF는 "브라우저가 쿠키를 자동으로 실어
                        // 보내기 때문에 남의 페이지에서도 인증된 요청이 나간다"는 것이 전제인데,
                        // 이 경로는 세션 쿠키가 아니라 X-Internal-Token 헤더로만 인증하는
                        // 파이썬 배치 전용이라 그 전제 자체가 성립하지 않는다.
                        // 빼지 않으면 배치의 POST(판단 결과 저장, fix-plan 저장)가 전부 403으로
                        // 막힌다 — GET(pending 조회)은 통과하므로 "판단은 다 하고 저장만 실패"라는,
                        // 로그만 봐서는 알아채기 어려운 형태로 깨진다.
                        //
                        // H2 콘솔(/h2-console/**)은 콘솔을 켰을 때만 제외한다. 콘솔 자체 로그인 폼이
                        // 이 앱의 CSRF 토큰을 모르고 POST하기 때문에, 빼지 않으면 앱에 로그인한
                        // 상태여도 콘솔 "Connect"가 403으로 막힌다. 꺼져 있을 때까지 빼 둘 이유는
                        // 없으니 설정값에 묶는다 — 켜 둔 동안은 콘솔이 CSRF 보호 없이 열리는 셈이라
                        // 로컬에서 잠깐 쓰고 반드시 다시 꺼야 한다.
                        .ignoringRequestMatchers(h2ConsoleEnabled
                                ? new String[]{"/api/ai/**", "/h2-console/**"}
                                : new String[]{"/api/ai/**"})
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                // 로그인 직후 첫 화면에서 XSRF-TOKEN 쿠키가 빠져 첫 POST가 403 나던 문제(CsrfCookieFilter 주석 참고)
                .addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class)
                // H2 콘솔은 기본으로 꺼둔다(application.properties). 임의 SQL 실행 콘솔이라
                // 인증 없이 열려 있으면 CREATE ALIAS ... AS $$ ... $$로 원격 코드 실행까지 가능하다
                // — 로컬에서 켜더라도 PUBLIC_URLS에 넣지 않으므로 앱 로그인은 여전히 필요하다.
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin())); // 홈 화면의 탭(iframe)이 같은 출처에서 화면을 띄우는 데 필요

        return http.build();
    }

    /**
     * 로그인이 필요한데 안 된 요청을 어떻게 끝낼지. /api/**는 401, 나머지(화면)는 로그인 페이지로.
     *
     * <p>defaultAuthenticationEntryPointFor로 API용만 덧붙이면, formLogin이 등록하는 로그인 페이지
     * 진입점이 "브라우저가 text/html을 요청할 때"로 한정돼 있어서 Accept에 text/html이 없는 화면 요청은
     * 먼저 등록된 API용(401)으로 떨어진다. 그래서 둘을 여기서 명시적으로 나눈다.
     */
    private DelegatingAuthenticationEntryPoint authenticationEntryPoint() {
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(AntPathRequestMatcher.antMatcher("/api/**"), new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
        entryPoint.setDefaultEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
        return entryPoint;
    }
}
