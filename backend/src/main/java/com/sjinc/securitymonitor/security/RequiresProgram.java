package com.sjinc.securitymonitor.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 이 API(클래스 또는 메서드)를 호출하려면 나열한 programId 중 하나의 UserProgramPermission이 필요함을 선언한다.
 * {@link RequiresProgramAuthorizationManager}가 리플렉션으로 읽으므로 SecurityConfig를 고칠 필요가 없다.
 * 메서드에 붙은 것이 클래스에 붙은 것보다 우선한다.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface RequiresProgram {
    String[] value();
}
