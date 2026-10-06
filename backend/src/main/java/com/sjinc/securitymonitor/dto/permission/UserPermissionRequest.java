package com.sjinc.securitymonitor.dto.permission;

import java.util.List;

/** 사용자별 권한관리 화면의 "저장" 버튼 클릭 시 전송하는 요청. 해당 사용자의 프로그램 권한을 이 목록으로 완전히 대체한다. */
public record UserPermissionRequest(List<ProgramPermissionItem> permissions) {
}
