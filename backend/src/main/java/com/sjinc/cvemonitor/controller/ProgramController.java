package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.dto.program.ProgramRequest;
import com.sjinc.cvemonitor.security.RequiresProgram;
import com.sjinc.cvemonitor.service.program.ProgramService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 프로그램 관리 화면(조회/저장/삭제 버튼)과, 사용자별 권한관리 화면의 프로그램 체크리스트가
 * 호출하는 REST API. 조회는 두 화면이 같이 쓰므로 둘 중 하나의 권한만 있어도 되지만, 실제
 * 프로그램을 추가/수정/삭제하는 건 "program-mng" 권한이 있어야 한다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/programs")
public class ProgramController {

    private final ProgramService programService;

    /** 화면의 "조회" 버튼 클릭 시 호출되는 엔드포인트. */
    @GetMapping
    @RequiresProgram({"program-mng", "user-permission-mng"})
    public List<Program> getPrograms() {
        return programService.getAllPrograms();
    }

    /** 화면의 "저장" 버튼 클릭 시 호출되는 엔드포인트. */
    @PostMapping
    @RequiresProgram("program-mng")
    public Program saveProgram(@RequestBody ProgramRequest request) {
        return programService.saveProgram(request);
    }

    /** 화면의 "삭제" 버튼 클릭 시 호출되는 엔드포인트. */
    @DeleteMapping("/{id}")
    @RequiresProgram("program-mng")
    public void deleteProgram(@PathVariable String id) {
        programService.deleteProgram(id);
    }
}
