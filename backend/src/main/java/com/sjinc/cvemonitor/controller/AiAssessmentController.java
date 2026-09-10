package com.sjinc.cvemonitor.controller;

import com.sjinc.cvemonitor.dto.ai.AiAssessmentRequest;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget;
import com.sjinc.cvemonitor.dto.ai.FixPlanRequest;
import com.sjinc.cvemonitor.dto.vulnerability.VulnerabilityInfo;
import com.sjinc.cvemonitor.service.ai.FixPlanService;
import com.sjinc.cvemonitor.service.vulnerability.VulnerabilityService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/**
 * 파이썬 AI 판단 배치가 호출하는 전용 API.
 *
 * <p>사람이 쓰는 화면이 아니라 서버 프로세스끼리 호출하는 용도라 세션 로그인 대신
 * {@code X-Internal-Token} 헤더 하나로만 인증한다(SecurityConfig에서 permitAll 처리).
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/ai")
public class AiAssessmentController {

    private final VulnerabilityService vulnerabilityService;
    private final FixPlanService fixPlanService;

    @Value("${ai.internal.token}")
    private String internalToken;

    @GetMapping("/vulnerabilities/pending")
    public List<VulnerabilityInfo> getPendingVulnerabilities(@RequestHeader("X-Internal-Token") String token) {
        verifyToken(token);
        return vulnerabilityService.getUnassessedVulnerabilities();
    }

    @PostMapping("/vulnerabilities/{id}/assessment")
    public void submitAssessment(@PathVariable Long id,
                                  @RequestHeader("X-Internal-Token") String token,
                                  @RequestBody AiAssessmentRequest request) {
        verifyToken(token);
        vulnerabilityService.applyAiAssessment(id, request);
    }

    @GetMapping("/fix-plans/pending")
    public List<AppFixPlanTarget> getPendingFixPlans(@RequestHeader("X-Internal-Token") String token) {
        verifyToken(token);
        return fixPlanService.getPendingFixPlanTargets();
    }

    @PostMapping("/apps/{appId}/fix-plan")
    public void submitFixPlan(@PathVariable Long appId,
                               @RequestHeader("X-Internal-Token") String token,
                               @RequestBody FixPlanRequest request) {
        verifyToken(token);
        fixPlanService.saveFixPlan(appId, request);
    }

    private void verifyToken(String token) {
        if (!internalToken.equals(token)) {
            // Security의 AccessDeniedException을 쓰면 익명 사용자는 /login으로 리다이렉트되어 버리므로,
            // API답게 401을 그대로 내려주기 위해 Security와 무관한 예외를 사용한다.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 내부 토큰입니다.");
        }
    }
}
