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
 * SecurityConfig의 anyRequest가 위임하는 판단 로직. 로그인을 기본으로 요구하고, 처리할 컨트롤러(메서드 우선)에
 * {@link RequiresProgram}이 있으면 그 프로그램 권한도 요구한다. 어노테이션을 빠뜨린 관리 화면 API는 로그인만으로
 * 열리므로, 새 관리 화면을 만들 때 반드시 붙인다.
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
        // 비로그인 요청에도 익명 토큰이 들어오고 그 isAuthenticated()는 true라, 익명 여부를 따로 봐야 로그인 전용
        // 화면·API를 막을 수 있다. 거부하면 ExceptionTranslationFilter가 로그인 페이지(화면) / 401(API)로 보낸다.
        if (authentication == null || !authentication.isAuthenticated() || TRUST_RESOLVER.isAnonymous(authentication)) {
            return new AuthorizationDecision(false);
        }

        RequiresProgram requiresProgram = resolveAnnotation(context.getRequest());
        if (requiresProgram == null) {
            // 이 API엔 어노테이션이 없다 — 별도 권한 없이 로그인만 하면 되는 API라는 뜻.
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
            // 핸들러가 없으면 어차피 뒤에서 404가 나므로 추가 권한 없이 넘어간다. 다만 fail-open이라
            // 핸들러가 있는데 예외가 난 경우 API가 로그인 전용으로 열리므로, 운영 로그에 보이도록 warn으로 남긴다.
            log.warn("핸들러를 찾지 못해 @RequiresProgram 검사를 건너뜁니다(권한 미요구로 처리): {}", request.getRequestURI(), e);
            return null;
        }
    }
}
