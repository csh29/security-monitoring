package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.dto.app.AppRequest;
import com.sjinc.securitymonitor.security.RequiresProgram;
import com.sjinc.securitymonitor.service.app.AppService;
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
 * 앱 관리·취약점 점검 화면이 호출하는 REST API. 목록 조회는 여러 화면이 쓰므로 로그인만 요구하고,
 * 등록/수정/삭제는 "app-mng" 권한이 필요하다 — 여기 등록한 저장소만 스캔 대상이 되기 때문이다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/apps")
public class AppController {

    private final AppService appService;

    @GetMapping
    public List<App> getApps() {
        return appService.getAllApps();
    }

    @PostMapping
    @RequiresProgram("app-mng")
    public App saveApp(@RequestBody AppRequest request) {
        return appService.saveApp(request);
    }

    @DeleteMapping("/{id}")
    @RequiresProgram("app-mng")
    public void deleteApp(@PathVariable Long id) {
        appService.deleteApp(id);
    }
}
