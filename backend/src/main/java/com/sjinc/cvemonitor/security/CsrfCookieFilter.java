package com.sjinc.cvemonitor.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 요청마다 CSRF 토큰을 화면을 그리기 전에 먼저 읽어서, XSRF-TOKEN 쿠키가 응답 헤더에 확실히 실리게 한다.
 *
 * <p>Spring Security 6은 토큰을 "누군가 값을 읽을 때" 만들고 그때 쿠키를 심는다. 로그인에 성공하면 기존
 * 토큰(쿠키)을 지우는데, 그 뒤 첫 화면에서 토큰을 처음 읽는 곳이 상단바 로그아웃 폼(페이지 중간)이다.
 * 거기까지 출력이 Tomcat 응답 버퍼(8KB)를 넘어 헤더가 이미 나간 뒤라 Set-Cookie가 조용히 버려졌고,
 * 쿠키가 없으니 공통 fetch 래퍼가 X-XSRF-TOKEN을 못 붙여 <b>로그인 직후 첫 저장·삭제가 403</b>이 났다
 * (그 403 응답에서야 쿠키가 심어져 한 번 더 누르면 됐다 — "가끔 403"으로 보인 이유).
 *
 * <p>SecurityConfig가 CsrfFilter 뒤에 등록한다. 검증 자체는 그대로 CsrfFilter가 한다.
 */
public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            csrfToken.getToken(); // 지연 토큰을 여기서 만들어 쿠키를 응답 초반에 심는다
        }
        filterChain.doFilter(request, response);
    }
}
