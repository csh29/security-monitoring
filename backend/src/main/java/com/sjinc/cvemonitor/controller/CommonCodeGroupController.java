package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.CommonCodeGroup;
import com.sjinc.cvemonitor.dto.commoncode.CommonCodeGroupRequest;
import com.sjinc.cvemonitor.service.commoncode.CommonCodeGroupService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** 공통코드관리 화면 좌측(마스터) 그룹 목록이 호출하는 REST API. */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/common-code-groups")
public class CommonCodeGroupController {

    private final CommonCodeGroupService commonCodeGroupService;

    @GetMapping
    public List<CommonCodeGroup> getGroups() {
        return commonCodeGroupService.getAllGroups();
    }

    @PostMapping
    public CommonCodeGroup saveGroup(@RequestBody CommonCodeGroupRequest request) {
        return commonCodeGroupService.saveGroup(request);
    }

    @DeleteMapping("/{codeGroup}")
    public void deleteGroup(@PathVariable String codeGroup) {
        commonCodeGroupService.deleteGroup(codeGroup);
    }
}
