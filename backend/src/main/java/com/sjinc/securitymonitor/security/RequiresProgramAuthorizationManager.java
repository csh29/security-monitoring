package com.sjinc.securitymonitor.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Arrays;
import java.util.function.Supplier;

/**
 * SecurityConfig의 유일한 authorizeHttpRequests 규칙(anyRequest)이 위임하는 실제 판단 로직.
 * 로그인 여부는 기본으로 요구하고, 요청을 처리할 컨트롤러(메서드 우선, 없으면 클래스)에
 * {@link RequiresProgram}이 붙어 있으면 그 programId 중 하나에 대한 UserProgramPermission도
 * 추가로 요구한다.
 *
 * <p>이 방식의 핵심은 "새 관리 화면 API가 생겨도 SecurityConfig를 고칠 필요가 없다"는 것이다 —
 * URL 패턴을 여기(혹은 SecurityConfig)에 하드코딩해서 나열하는 대신, 컨트롤러 자신이
 * {@code @RequiresProgram("app-mng")}처럼 자기 권한 요건을 선언하면 이 매니저가
 * 리플렉션으로 읽어서 적용한다. 그래서 어노테이션을 깜빡한 새 컨트롤러는 "로그인만 하면
 * 되는 API"가 되는데, 이건 기존 코드 전체가 그랬던(그래서 이 보안 검토가 나온) 상태와 같은
 * 실패 모드이니 — 관리 화면을 새로 만들 때 이 어노테이션을 붙이는 걸 코드 리뷰 체크리스트에
 * 넣어야 한다.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RequiresProgramAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

    private final RequestMappingHandlerMapping requestMappingHandlerMapping;
    private final ProgramAccessGuard programAccess;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, RequestAuthorizationContext context) {
        Authentication authentication = authenticationSupplier.get();
        // 로그인하지 않은 요청도 Spring Security는 익명 토큰(AnonymousAuthenticationToken)을 넣어 주고,
        // 그 토큰의 isAuthenticated()는 true다. isAuthenticated()만 보면 비로그인 사용자가 "로그인만 하면
        // 되는" 화면·API(홈, 취약점 관리/조회, @RequiresProgram 없는 API)를 그대로 통과한다 — 실제로 그랬다.
        // 익명이면 거부해야 ExceptionTranslationFilter가 로그인 페이지(화면) / 401(API)로 보낸다.
        if (authentication == null || !authentication.isAuthenticated() || TRUST_RESOLVER.isAnonymous(authentication)) {
            return new AuthorizationDecision(false);
        }

        RequiresProgram requiresProgram = resolveAnnotation(context.getRequest());
        if (requiresProgram == null) {
            // 이 API엔 어노테이션이 없다 — 별도 권한 없이 로그인만 하면 되는 API(고정 메뉴 등)라는 뜻.
            return new AuthorizationDecision(true);
        }

        boolean granted = Arrays.stream(requiresProgram.value())
                .anyMatch(programId -> programAccess.check(authentication.getName(), programId));
        return new AuthorizationDecision(granted);
    }

    private RequiresProgram resolveAnnotation(HttpServletRequest request) {
        try {
            HandlerExecutionChain chain = requestMappingHandlerMapping.getHandler(request);
            if (chain == null || !(chain.getHandler() instanceof HandlerMethod handlerMethod)) {
                return null;
            }
            RequiresProgram methodLevel = handlerMethod.getMethodAnnotation(RequiresProgram.class);
            return methodLevel != null ? methodLevel : handlerMethod.getBeanType().getAnnotation(RequiresProgram.class);
        } catch (Exception e) {
            // 이 시점에 핸들러를 못 찾으면(경로 자체가 없는 등) 어차피 뒤에서 404가 난다 —
            // 권한을 판단할 대상이 없다는 뜻이라 추가 권한을 요구하지 않고 그냥 넘어간다.
            //
            // 다만 이 경로는 "권한 검사를 건너뛴다"는 뜻이라 fail-open이다. 예상과 달리 핸들러가
            // 있는 요청에서 예외가 나면 그 API가 조용히 로그인 전용으로 열리므로, 눈에 띄도록
            // warn으로 남긴다(debug면 운영 로그 레벨에서 아예 보이지 않는다).
            log.warn("핸들러를 찾지 못해 @RequiresProgram 검사를 건너뜁니다(권한 미요구로 처리): {}", request.getRequestURI(), e);
            return null;
        }
    }
}
