package com.sjinc.cvemonitor.service.program;

import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.dto.program.ProgramRequest;
import com.sjinc.cvemonitor.repository.ProgramRepository;
import com.sjinc.cvemonitor.repository.UserProgramPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 로그인한 사용자가 권한을 가진 추가 프로그램(메뉴) 목록을 조회한다. */
@Service
@RequiredArgsConstructor
public class ProgramService {

    private final ProgramRepository programRepository;
    private final UserProgramPermissionRepository userProgramPermissionRepository;

    @Transactional(readOnly = true)
    public List<Program> getAccessiblePrograms(String username) {
        if (username == null || username.isBlank()) {
            return List.of();
        }
        return userProgramPermissionRepository.findAccessiblePrograms(username);
    }

    /** 프로그램 전체 목록. 프로그램 관리 화면의 그리드, 사용자별 권한관리 화면의 체크리스트 등에서 공용으로 쓰인다. */
    @Transactional(readOnly = true)
    public List<Program> getAllPrograms() {
        return programRepository.findAllSorted();
    }

    /** 프로그램 관리 화면의 "저장" 버튼. request.id()가 이미 존재하는 program_id면 수정, 아니면 신규 등록. */
    @Transactional
    public Program saveProgram(ProgramRequest request) {
        Program program = Program.builder()
                .programId(request.id())
                .name(request.name())
                .url(request.url())
                .sortOrder(request.sortOrder())
                .useYn(request.useYn())
                .build();
        return programRepository.save(program);
    }

    /** 프로그램 관리 화면의 "삭제" 버튼. */
    @Transactional
    public void deleteProgram(String id) {
        programRepository.deleteById(id);
    }
}
