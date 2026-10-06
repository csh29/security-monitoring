package com.sjinc.securitymonitor.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 이 API(클래스 전체 또는 메서드 하나)를 호출하려면 나열한 programId 중 하나에 대한
 * UserProgramPermission이 있어야 한다는 것을 선언한다.
 *
 * <p>{@link RequiresProgramAuthorizationManager}가 SecurityConfig의 URL 패턴 목록 대신, 요청을
 * 처리할 컨트롤러 메서드에 붙은 이 어노테이션을 리플렉션으로 읽어 판단한다 — 새 관리 화면 API를
 * 추가할 때 SecurityConfig를 고칠 필요 없이 그 컨트롤러에 이 어노테이션만 붙이면 자동으로
 * 접근 제어가 걸린다. 메서드에 붙은 어노테이션이 클래스에 붙은 것보다 우선한다.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface RequiresProgram {
    String[] value();
}
