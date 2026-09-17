package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.domain.CommonCode;
import com.sjinc.cvemonitor.dto.commoncode.CommonCodeRequest;
import com.sjinc.cvemonitor.service.commoncode.CommonCodeService;
import lombok.RequiredArgsConstructor;
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
 * 공통코드관리 화면 우측(디테일 코드 그리드)과, 다른 화면들이 select를 채울 때 호출하는 API.
 * group은 항상 필수 — 어떤 그룹의 코드인지 없이는 의미가 없다. select용 호출은 사용중인 코드만
 * 받으면 되지만, 관리 화면은 비활성 코드도 편집해야 하므로 includeInactive=true로 전부 받는다.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/common-codes")
public class CommonCodeController {

    private final CommonCodeService commonCodeService;

    @GetMapping
    public List<CommonCode> getCodes(@RequestParam String group,
                                      @RequestParam(required = false, defaultValue = "false") boolean includeInactive) {
        return includeInactive
                ? commonCodeService.getAllCodesByGroup(group)
                : commonCodeService.getCodesByGroup(group);
    }

    @PostMapping
    public CommonCode saveCode(@RequestBody CommonCodeRequest request) {
        return commonCodeService.saveCode(request);
    }

    @DeleteMapping("/{id}")
    public void deleteCode(@PathVariable Long id) {
        commonCodeService.deleteCode(id);
    }
}
