package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.dto.app.AppRequest;
import com.sjinc.cvemonitor.security.RequiresProgram;
import com.sjinc.cvemonitor.service.app.AppService;
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
 * 앱 관리 화면(조회/저장/삭제 버튼) 및 취약점 조회 화면이 호출하는 REST API.
 * 목록 조회는 취약점 조회(고정 메뉴, 전체 사용자 대상) 화면도 같이 쓰므로 로그인만 하면 되지만,
 * 앱을 등록/수정/삭제하는 건 "app-management" 권한이 있어야 한다. 여기서 등록한 repoUrl/branch만
 * 스캔 대상이 될 수 있으므로(ScanOrchestrationService), 사실상 스캔 가능한 저장소 목록을
 * 통제하는 진입점이다.
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
    @RequiresProgram("app-management")
    public App saveApp(@RequestBody AppRequest request) {
        return appService.saveApp(request);
    }

    @DeleteMapping("/{id}")
    @RequiresProgram("app-management")
    public void deleteApp(@PathVariable Long id) {
        appService.deleteApp(id);
    }
}
