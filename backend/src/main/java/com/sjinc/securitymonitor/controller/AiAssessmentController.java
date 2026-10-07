package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.dto.ai.AiAssessmentRequest;
import com.sjinc.securitymonitor.dto.ai.AiBatchStatus;
import com.sjinc.securitymonitor.dto.ai.AppFixPlanTarget;
import com.sjinc.securitymonitor.dto.ai.CveSummaryRequest;
import com.sjinc.securitymonitor.dto.ai.CveSummaryTarget;
import com.sjinc.securitymonitor.dto.ai.FixPlanRequest;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewRequest;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewTarget;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactTarget;
import com.sjinc.securitymonitor.dto.vulnerability.VulnerabilityInfo;
import com.sjinc.securitymonitor.service.ai.AiAssessmentTriggerService;
import com.sjinc.securitymonitor.service.ai.CveSummaryService;
import com.sjinc.securitymonitor.service.ai.FixPlanService;
import com.sjinc.securitymonitor.service.ai.SecureCodeAiReviewService;
import com.sjinc.securitymonitor.service.ai.UpgradeImpactService;
import com.sjinc.securitymonitor.service.vulnerability.VulnerabilityService;
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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

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
    private final CveSummaryService cveSummaryService;
    private final UpgradeImpactService upgradeImpactService;
    private final SecureCodeAiReviewService secureCodeAiReviewService;
    private final AiAssessmentTriggerService aiAssessmentTriggerService;

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

    @GetMapping("/summaries/pending")
    public List<CveSummaryTarget> getPendingSummaries(@RequestHeader("X-Internal-Token") String token) {
        verifyToken(token);
        return cveSummaryService.getPendingSummaryTargets();
    }

    @PostMapping("/summaries")
    public void submitSummary(@RequestHeader("X-Internal-Token") String token,
                              @RequestBody CveSummaryRequest request) {
        verifyToken(token);
        cveSummaryService.saveSummary(request);
    }

    @GetMapping("/impacts/pending")
    public List<UpgradeImpactTarget> getPendingImpacts(@RequestHeader("X-Internal-Token") String token) {
        verifyToken(token);
        return upgradeImpactService.getPendingTargets();
    }

    @PostMapping("/impacts")
    public void submitImpact(@RequestHeader("X-Internal-Token") String token,
                             @RequestBody UpgradeImpactRequest request) {
        verifyToken(token);
        upgradeImpactService.saveImpact(request);
    }

    @GetMapping("/secure-code/pending")
    public List<SecureCodeReviewTarget> getPendingSecureCodeReviews(@RequestHeader("X-Internal-Token") String token) {
        verifyToken(token);
        return secureCodeAiReviewService.getPendingTargets();
    }

    @PostMapping("/secure-code/{id}/review")
    public void submitSecureCodeReview(@PathVariable Long id,
                                       @RequestHeader("X-Internal-Token") String token,
                                       @RequestBody SecureCodeReviewRequest request) {
        verifyToken(token);
        secureCodeAiReviewService.saveReview(id, request);
    }

    @GetMapping("/status")
    /** 배치 종류(CVE / SECURE_CODE)별 실행 상태. 두 종류는 따로 떠서 동시에 돌 수 있다. */
    public Map<AiAssessmentTriggerService.BatchKind, AiBatchStatus> getStatus(@RequestHeader("X-Internal-Token") String token) {
        verifyToken(token);
        return aiAssessmentTriggerService.getStatus();
    }

    private void verifyToken(String token) {
        // String.equals()는 첫 불일치 문자에서 바로 반환해서 비교에 걸리는 시간이 일치하는
        // 접두사 길이에 비례한다 — 이론상 타이밍 공격으로 토큰을 한 글자씩 알아낼 수 있다.
        // MessageDigest.isEqual은 항상 배열 전체를 비교해서 이 시간차를 없앤다.
        boolean valid = token != null
                && MessageDigest.isEqual(internalToken.getBytes(StandardCharsets.UTF_8), token.getBytes(StandardCharsets.UTF_8));
        if (!valid) {
            // Security의 AccessDeniedException을 쓰면 익명 사용자는 /login으로 리다이렉트되어 버리므로,
            // API답게 401을 그대로 내려주기 위해 Security와 무관한 예외를 사용한다.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 내부 토큰입니다.");
        }
    }
}
