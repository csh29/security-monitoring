package com.sjinc.securitymonitor.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 요청마다 CSRF 토큰을 화면 출력 전에 읽어 XSRF-TOKEN 쿠키가 응답 헤더에 확실히 실리게 한다. 토큰은 처음 읽힐 때
 * 쿠키로 심기는데, 페이지 중간에서 읽으면 응답 버퍼를 넘겨 헤더가 이미 나간 뒤라 쿠키가 버려지고 로그인 직후 첫 POST가
 * 403이 나기 때문이다. SecurityConfig가 CsrfFilter 뒤에 등록하며, 검증은 CsrfFilter가 한다.
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
