package com.sjinc.securitymonitor.service.permission;

import com.sjinc.securitymonitor.domain.UserProgramPermission;
import com.sjinc.securitymonitor.dto.permission.ProgramPermissionItem;
import com.sjinc.securitymonitor.repository.ProgramRepository;
import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import com.sjinc.securitymonitor.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 사용자별 권한관리 화면(사용자 1명에게 부여된 프로그램 권한 조회/저장)을 담당한다. */
@Service
@RequiredArgsConstructor
public class UserPermissionService {

    private final UserRepository userRepository;
    private final ProgramRepository programRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;

    /** 해당 사용자가 현재 권한을 가진 프로그램과 그 버튼 권한 목록. */
    @Transactional(readOnly = true)
    public List<ProgramPermissionItem> getPermissions(Long userId) {
        return userProgramPermissionRepository.findByUserId(userId).stream()
                .map(ProgramPermissionItem::from)
                .toList();
    }

    /** 해당 사용자의 프로그램·버튼 권한을 items로 완전히 대체한다. */
    @Transactional
    public void replacePermissions(Long userId, List<ProgramPermissionItem> items) {
        userProgramPermissionRepository.deleteByUserId(userId);

        var user = userRepository.getReferenceById(userId);
        var permissions = items.stream()
                .map(item -> UserProgramPermission.builder()
                        .user(user)
                        .program(programRepository.getReferenceById(item.programId()))
                        .searchYn(yn(item.searchYn()))
                        .newYn(yn(item.newYn()))
                        .saveYn(yn(item.saveYn()))
                        .deleteYn(yn(item.deleteYn()))
                        .resetYn(yn(item.resetYn()))
                        .etc1Yn(yn(item.etc1Yn()))
                        .etc2Yn(yn(item.etc2Yn()))
                        .etc3Yn(yn(item.etc3Yn()))
                        .etc4Yn(yn(item.etc4Yn()))
                        .etc5Yn(yn(item.etc5Yn()))
                        .build())
                .toList();

        userProgramPermissionRepository.saveAll(permissions);
    }

    /** "Y"만 Y, 그 외(null 포함)는 전부 N — 컬럼이 NOT NULL이라 빈 값이 그대로 들어가지 않게 한다. */
    private static String yn(String value) {
        return "Y".equals(value) ? "Y" : "N";
    }
}
