package com.sjinc.cvemonitor.security;

import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 사이드바 메뉴 노출 여부(ProgramService.getAccessiblePrograms)와 똑같은 UserProgramPermission
 * 데이터로 추가 프로그램(프로그램 관리/사용자 관리/사용자별 권한관리/앱 관리/공통코드관리) API의
 * 실제 접근도 막는다. 메뉴를 안 보여주는 것만으로는 접근 제어가 되지 않는다 — 컨트롤러가
 * {@code @PreAuthorize("@programAccess.check(authentication.name, '프로그램ID')")}로 이 빈을
 * 호출해서 서버 쪽에서도 검증한다.
 */
@Component("programAccess")
@RequiredArgsConstructor
public class ProgramAccessGuard {

    private final UserProgramPermissionRepository userProgramPermissionRepository;

    public boolean check(String username, String programId) {
        if (username == null) {
            return false;
        }
        return userProgramPermissionRepository.findAccessiblePrograms(username).stream()
                .anyMatch(program -> program.getProgramId().equals(programId));
    }
}
