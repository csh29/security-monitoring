package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.domain.ScanHistory;
import com.sjinc.securitymonitor.service.scan.ScanHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 스캔 이력 화면(고정 메뉴)이 호출하는 조회 API. 스캔 실행(/api/scan)과 취약점 조회가 로그인만으로 열려 있어
 * 그 실행 기록도 같은 기준으로 둔다 — 그래서 @RequiresProgram을 붙이지 않는다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/scan-histories")
public class ScanHistoryController {

    private final ScanHistoryService scanHistoryService;

    /** appId를 주지 않으면 전체 앱. 최신순으로 최대 {@code ScanHistoryService.MAX_ROWS}건. */
    @GetMapping
    public List<ScanHistory> getHistories(@RequestParam(required = false) Long appId) {
        return scanHistoryService.getHistories(appId);
    }
}
