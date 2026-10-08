package com.sjinc.securitymonitor.dto.app;

/**
 * 앱 관리 화면의 "저장" 버튼 클릭 시 전송하는 요청. id가 없으면 신규 등록, 있으면 수정.
 * sourceType은 공통코드 APP_SOURCE(GIT/UPLOAD). 비어 있으면 GIT — 이 값이 생기기 전 화면·요청과 맞추기 위함.
 */
public record AppRequest(Long id, String repoUrl, String branch, String systemName, String description,
                         String managerName, String managerEmail, String sourceType) {
}
