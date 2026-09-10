package com.sjinc.cvemonitor.dto.user;

/**
 * 사용자 관리 화면의 "저장" 버튼 클릭 시 전송하는 요청.
 * id가 없으면 신규 등록, 있으면 수정. password가 비어있으면(수정 시) 기존 비밀번호를 유지한다.
 */
public record UserRequest(Long id, String username, String password, String role) {
}
