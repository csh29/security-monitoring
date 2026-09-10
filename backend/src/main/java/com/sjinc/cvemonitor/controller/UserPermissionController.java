package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.dto.permission.UserPermissionRequest;
import com.sjinc.cvemonitor.service.permission.UserPermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 사용자별 권한관리 화면이 호출하는 REST API. */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/permissions")
public class UserPermissionController {

    private final UserPermissionService userPermissionService;

    /** 화면의 "조회" 버튼 클릭 시 호출되는 엔드포인트. 해당 사용자가 권한을 가진 프로그램 id 목록. */
    @GetMapping("/{userId}")
    public List<String> getGrantedProgramIds(@PathVariable Long userId) {
        return userPermissionService.getGrantedProgramIds(userId);
    }

    /** 화면의 "저장" 버튼 클릭 시 호출되는 엔드포인트. 해당 사용자의 프로그램 권한을 통째로 교체한다. */
    @PostMapping("/{userId}")
    public void savePermissions(@PathVariable Long userId, @RequestBody UserPermissionRequest request) {
        userPermissionService.replacePermissions(userId, request.programIds());
    }
}
