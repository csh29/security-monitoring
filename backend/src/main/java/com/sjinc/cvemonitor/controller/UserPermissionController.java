package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.dto.permission.ProgramPermissionItem;
import com.sjinc.cvemonitor.dto.permission.UserPermissionRequest;
import com.sjinc.cvemonitor.security.RequiresProgram;
import com.sjinc.cvemonitor.service.permission.UserPermissionService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 사용자별 권한관리 화면이 호출하는 REST API. "user-permission-management" 권한이 있어야 한다 —
 * 그렇지 않으면 임의 계정에 아무 프로그램 권한이나 부여/박탈할 수 있는 권한 상승 경로가 된다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/permissions")
@RequiresProgram("user-permission-management")
public class UserPermissionController {

    private final UserPermissionService userPermissionService;

    /** 화면의 "조회" 버튼 클릭 시 호출되는 엔드포인트. 해당 사용자가 권한을 가진 프로그램과 그 버튼 권한 목록. */
    @GetMapping("/{userId}")
    public List<ProgramPermissionItem> getPermissions(@PathVariable Long userId) {
        return userPermissionService.getPermissions(userId);
    }

    /** 화면의 "저장" 버튼 클릭 시 호출되는 엔드포인트. 해당 사용자의 프로그램·버튼 권한을 통째로 교체한다. */
    @PostMapping("/{userId}")
    public void savePermissions(@PathVariable Long userId, @RequestBody UserPermissionRequest request) {
        userPermissionService.replacePermissions(userId, request.permissions());
    }
}
