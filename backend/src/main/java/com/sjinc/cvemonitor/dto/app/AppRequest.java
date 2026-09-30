package com.sjinc.cvemonitor.dto.app;

/** 앱 관리 화면의 "저장" 버튼 클릭 시 전송하는 요청. id가 없으면 신규 등록, 있으면 수정. */
public record AppRequest(Long id, String repoUrl, String branch, String systemName, String description,
                         String managerName, String managerEmail) {
}
