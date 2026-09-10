package com.sjinc.cvemonitor.service.permission;

import com.sjinc.cvemonitor.domain.UserProgramPermission;
import com.sjinc.cvemonitor.repository.ProgramRepository;
import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import com.sjinc.cvemonitor.repository.UserRepository;
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

    /** 해당 사용자가 현재 권한을 가진 프로그램 id(program_id) 목록. */
    @Transactional(readOnly = true)
    public List<String> getGrantedProgramIds(Long userId) {
        return userProgramPermissionRepository.findProgramIdsByUserId(userId);
    }

    /** 해당 사용자의 프로그램 권한을 programIds로 완전히 대체한다. */
    @Transactional
    public void replacePermissions(Long userId, List<String> programIds) {
        userProgramPermissionRepository.deleteByUserId(userId);

        var user = userRepository.getReferenceById(userId);
        var permissions = programIds.stream()
                .map(programId -> UserProgramPermission.builder()
                        .user(user)
                        .program(programRepository.getReferenceById(programId))
                        .build())
                .toList();

        userProgramPermissionRepository.saveAll(permissions);
    }
}
