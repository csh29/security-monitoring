package com.sjinc.securitymonitor.service.program;

import com.sjinc.securitymonitor.domain.Program;
import com.sjinc.securitymonitor.domain.ProgramButton;
import com.sjinc.securitymonitor.dto.program.PageButtonView;
import com.sjinc.securitymonitor.dto.program.ProgramRequest;
import com.sjinc.securitymonitor.repository.ProgramRepository;
import com.sjinc.securitymonitor.repository.UserProgramPermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

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
                .programNm(request.programNm())
                .url(request.url())
                .sortOrder(request.sortOrder())
                .useYn(request.useYn())
                .searchYn(yn(request.searchYn()))
                .newYn(yn(request.newYn()))
                .saveYn(yn(request.saveYn()))
                .deleteYn(yn(request.deleteYn()))
                .resetYn(yn(request.resetYn()))
                .etc1Nm(blankToNull(request.etc1Nm()))
                .etc2Nm(blankToNull(request.etc2Nm()))
                .etc3Nm(blankToNull(request.etc3Nm()))
                .etc4Nm(blankToNull(request.etc4Nm()))
                .etc5Nm(blankToNull(request.etc5Nm()))
                .build();
        return programRepository.save(program);
    }

    /** 프로그램 관리 화면의 "삭제" 버튼. */
    @Transactional
    public void deleteProgram(String id) {
        programRepository.deleteById(id);
    }

    /**
     * 화면을 열 때 우측 상단 툴바에 그릴 공통 버튼. 프로그램 관리에서 그 프로그램이 쓰도록 한 버튼 중
     * 사용자별 권한관리에서 이 사용자에게 허용한 것만, ProgramButton 순서대로 돌려준다.
     *
     * <p>Program 테이블에 없는 화면(고정 메뉴)이면 empty — 버튼은 호출하는 쪽(ViewController)이 정한다.
     * 등록된 화면인데 권한 행이 없으면 빈 목록이다(어차피 ViewController가 화면 접근부터 막는다).
     */
    @Transactional(readOnly = true)
    public Optional<List<PageButtonView>> getPageButtons(String username, String programId) {
        return programRepository.findById(programId).map(program -> userProgramPermissionRepository
                .findByUserUsernameAndProgramProgramId(username, programId)
                .map(perm -> Arrays.stream(ProgramButton.values())
                        .filter(button -> program.uses(button) && perm.allows(button))
                        .map(button -> PageButtonView.of(button, program.buttonLabel(button)))
                        .toList())
                .orElse(List.of()));
    }

    private static String yn(String value) {
        return "Y".equals(value) ? "Y" : "N";
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
