package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.ComCdGroup;
import com.sjinc.cvemonitor.dto.comcd.ComCdGroupRequest;
import com.sjinc.cvemonitor.security.RequiresProgram;
import com.sjinc.cvemonitor.service.comcd.ComCdGroupService;
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
 * 공통코드 마스터(그룹) REST API. 등록·수정·삭제는 공통코드마스터 관리 화면 전용이라
 * "com-cd-master-mng" 권한이 필요하다. 목록 조회는 공통코드 관리 화면도 좌측 그리드를
 * 채우려고 부르므로, 두 화면 중 어느 쪽 권한이 있어도 된다(메서드 어노테이션이 클래스 것보다 우선).
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/com-cd-groups")
@RequiresProgram("com-cd-master-mng")
public class ComCdGroupController {

    private final ComCdGroupService comCdGroupService;

    @GetMapping
    @RequiresProgram({"com-cd-master-mng", "com-cd-mng"})
    public List<ComCdGroup> getGroups() {
        return comCdGroupService.getAllGroups();
    }

    @PostMapping
    public ComCdGroup saveGroup(@RequestBody ComCdGroupRequest request) {
        return comCdGroupService.saveGroup(request);
    }

    @DeleteMapping("/{codeGroup}")
    public void deleteGroup(@PathVariable String codeGroup) {
        comCdGroupService.deleteGroup(codeGroup);
    }
}
