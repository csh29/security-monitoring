package com.sjinc.cvemonitor.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 폼 로그인 기반 세션 인증의 기본 구조.
 *
 * <p>{@code /login} 화면(뷰)만 비로그인 상태로 열어두고, 그 외 모든 요청은 인증을 요구한다.
 * {@code /api/**}는 화면단 AJAX 호출이 CSRF 토큰을 싣지 않는 것을 전제로 CSRF 검증에서 제외했다.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String[] PUBLIC_URLS = {
            "/login", "/css/**", "/js/**", "/assets/**", "/favicon.ico", "/h2-console/**",
            "/api/ai/**", // 세션 로그인이 없는 파이썬 AI 배치용 API. 대신 X-Internal-Token 헤더로 자체 인증한다.
            "/error" // 없으면 sendError()로 인한 /error 내부 포워딩까지 인증을 요구해서, 401/404 응답이 로그인 리다이렉트로 바뀌어 버린다.
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll())
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll())
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**", "/h2-console/**"))
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin())); // h2-console iframe 허용

        return http.build();
    }
}
