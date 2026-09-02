package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.dto.git.ScanRequest;
import com.sjinc.cvemonitor.dto.git.ScanResult;
import com.sjinc.cvemonitor.service.scan.ScanOrchestrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final ScanOrchestrationService scanOrchestrationService;

    /** 화면의 "검증" 버튼 클릭 시 호출되는 엔드포인트. */
    @PostMapping
    public ScanResult scan(@RequestBody ScanRequest request) throws Exception {
        return scanOrchestrationService.scanRepository(request.repoUrl(), request.branch());
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleScanError(Exception e) {
        return "스캔 실패: " + e.getMessage();
    }
}