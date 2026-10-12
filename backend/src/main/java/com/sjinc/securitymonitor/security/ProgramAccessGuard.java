package com.sjinc.securitymonitor.security;

import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 사이드바 메뉴 노출과 같은 UserProgramPermission 데이터로 추가 프로그램 API의 실제 접근도 막는다.
 * 메뉴를 숨기는 것만으로는 접근 제어가 되지 않으므로 서버에서도 이 빈으로 검증한다.
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
