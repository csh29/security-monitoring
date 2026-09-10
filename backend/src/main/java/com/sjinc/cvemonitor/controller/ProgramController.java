package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.dto.program.ProgramRequest;
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

/** 프로그램 관리 화면(조회/저장/삭제 버튼)이 호출하는 REST API. */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/programs")
public class ProgramController {

    private final ProgramService programService;

    /** 화면의 "조회" 버튼 클릭 시 호출되는 엔드포인트. */
    @GetMapping
    public List<Program> getPrograms() {
        return programService.getAllPrograms();
    }

    /** 화면의 "저장" 버튼 클릭 시 호출되는 엔드포인트. */
    @PostMapping
    public Program saveProgram(@RequestBody ProgramRequest request) {
        return programService.saveProgram(request);
    }

    /** 화면의 "삭제" 버튼 클릭 시 호출되는 엔드포인트. */
    @DeleteMapping("/{id}")
    public void deleteProgram(@PathVariable String id) {
        programService.deleteProgram(id);
    }
}
