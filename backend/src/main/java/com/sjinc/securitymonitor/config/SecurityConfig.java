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
 * 폼 로그인 세션 인증과 관리 화면 API 접근 제어 정책. 허용 목록 외 요청은 모두
 * {@link RequiresProgramAuthorizationManager}가 로그인·프로그램 권한으로 판단(fail closed)하므로,
 * 새 API는 여기를 고치지 않고 컨트롤러에 {@code @RequiresProgram}만 붙이면 된다.
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
                // 미로그인 /api/** 요청은 302 대신 401로 끝낸다. 302면 fetch가 로그인 페이지 HTML을 200으로 받아
                // JSON 파싱 오류가 나기 때문이다. 401은 공통 fetch 래퍼가 로그인 페이지로 보내고, 화면 요청은 리다이렉트한다.
                .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint()))
                // /api/**도 CSRF 검증을 받는다. 쿠키의 토큰을 공통 fetch 래퍼가 X-XSRF-TOKEN 헤더로 실어 보내며(원문 비교),
                // 제외하면 악성 페이지가 로그인한 관리자 브라우저로 상태 변경 요청을 보낼 수 있다.
                .csrf(csrf -> csrf
                        // /api/ai/**는 세션 쿠키가 아닌 X-Internal-Token으로만 인증하는 배치 전용이라 CSRF 전제가 없어 제외한다
                        // (빼지 않으면 배치 POST만 403으로 조용히 실패한다). H2 콘솔은 자체 폼이 토큰을 모르므로
                        // 콘솔을 켰을 때만 제외한다 — 켜 둔 동안은 CSRF 보호가 없으니 로컬에서만 잠깐 쓴다.
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
     * 미로그인 요청 처리: /api/**는 401, 나머지(화면)는 로그인 페이지로. formLogin 기본 진입점은 Accept에
     * text/html이 있을 때만 적용돼 화면 요청이 401로 떨어질 수 있어, 둘을 여기서 명시적으로 나눈다.
     */
    private DelegatingAuthenticationEntryPoint authenticationEntryPoint() {
        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(AntPathRequestMatcher.antMatcher("/api/**"), new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        DelegatingAuthenticationEntryPoint entryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
        entryPoint.setDefaultEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
        return entryPoint;
    }
}
