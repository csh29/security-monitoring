package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.dto.scan.ScanRequest;
import com.sjinc.cvemonitor.dto.scan.ScanResult;
import com.sjinc.cvemonitor.service.scan.ScanOrchestrationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
@Slf4j
public class ScanController {

    private final ScanOrchestrationService scanOrchestrationService;

    /** 화면의 "검증" 버튼 클릭 시 호출되는 엔드포인트. */
    @PostMapping
    public ScanResult scan(@RequestBody ScanRequest request, Principal principal) throws Exception {
        return scanOrchestrationService.scanRepository(request.repoUrl(), request.branch(),
                principal != null ? principal.getName() : null);
    }

    /** 앱 관리에 등록되지 않은 repoUrl/branch 등, 요청 자체가 잘못된 경우(400)와 스캔 도중 실패(500)를 구분한다. */
    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleInvalidRequest(IllegalArgumentException e) {
        return e.getMessage();
    }

    /**
     * 예외 메시지를 그대로 내려주면 Maven/JGit이 만든 메시지에 서버의 임시 디렉터리 경로 같은
     * 내부 정보가 섞여 나간다. 원인은 서버 로그에 남기고, 화면에는 고정 문구만 준다.
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleScanError(Exception e) {
        log.error("스캔 실패", e);
        return "스캔에 실패했습니다. 서버 로그를 확인해주세요.";
    }
}