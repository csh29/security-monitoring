package com.sjinc.securitymonitor.dto.user;

/**
 * 상단바 "비밀번호 변경" — 로그인한 본인의 비밀번호를 바꾼다. 대상 계정은 요청 본문이 아니라 로그인
 * 세션(Principal)으로 정하므로 id/username을 받지 않는다(UserController.changeMyPassword).
 */
public record PasswordChangeRequest(String currentPassword, String newPassword) {
}
