package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.dto.ai.FixPlanResponse;
import com.sjinc.securitymonitor.service.ai.FixPlanService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 사람이 로그인해서 완성된 fix-plan(수정된 pom.xml, 근거, 미해결 CVE)을 확인하는 화면/API. */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/fix-plans")
public class FixPlanController {

    private final FixPlanService fixPlanService;

    @GetMapping("/{appId}")
    public FixPlanResponse getFixPlan(@PathVariable Long appId) {
        return fixPlanService.getFixPlan(appId);
    }
}
