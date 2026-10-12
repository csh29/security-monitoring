package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.domain.ComCd;
import com.sjinc.securitymonitor.dto.comcd.ComCdRequest;
import com.sjinc.securitymonitor.security.RequiresProgram;
import com.sjinc.securitymonitor.service.comcd.ComCdService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 공통코드 관리 화면과 각 화면의 select가 호출하는 API. 사용중 코드 조회는 로그인만 요구하고, includeInactive=true와
 * 저장/삭제는 "com-cd-mng" 권한이 필요하다. getCodes만 {@code @PreAuthorize}를 쓰는 것은 쿼리 파라미터 값에 따라
 * 권한을 요구해야 해서 메서드 전체에 걸리는 {@code @RequiresProgram}으로는 표현할 수 없기 때문이다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/com-cds")
public class ComCdController {

    private final ComCdService comCdService;

    @GetMapping
    @PreAuthorize("!#includeInactive or @programAccess.check(authentication.name, 'com-cd-mng')")
    public List<ComCd> getCodes(@RequestParam String group,
                                      @RequestParam(required = false, defaultValue = "false") boolean includeInactive) {
        return includeInactive
                ? comCdService.getAllCodesByGroup(group)
                : comCdService.getCodesByGroup(group);
    }

    @PostMapping
    @RequiresProgram("com-cd-mng")
    public ComCd saveCode(@RequestBody ComCdRequest request) {
        return comCdService.saveCode(request);
    }

    @DeleteMapping("/{id}")
    @RequiresProgram("com-cd-mng")
    public void deleteCode(@PathVariable Long id) {
        comCdService.deleteCode(id);
    }
}
