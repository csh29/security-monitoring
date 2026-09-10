package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.dto.app.AppRequest;
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

/** 앱 관리 화면(조회/저장/삭제 버튼) 및 취약점 조회 화면이 호출하는 REST API. */
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
    public App saveApp(@RequestBody AppRequest request) {
        return appService.saveApp(request);
    }

    @DeleteMapping("/{id}")
    public void deleteApp(@PathVariable Long id) {
        appService.deleteApp(id);
    }
}
