package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.dto.securecode.TraceRuleProposalRequest;
import com.sjinc.securitymonitor.dto.securecode.TraceRuleProposalView;
import com.sjinc.securitymonitor.security.RequiresProgram;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

/**
 * 코드 점검이 만든 추적 규칙(trace-rules.yml) 초안 — 코드 점검 화면의 "추적 규칙 초안".
 * 목록은 점검 화면과 같이 로그인만 요구하고, 반영·무시는 앱 관리 권한이 필요하다 — 반영한 규칙은 모든 앱의 판정을 바꾼다
 * (소스 업로드 점검과 같은 기준).
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/secure-code/trace-rule-proposals")
public class TraceRuleProposalController {

    private final TraceRuleService traceRuleService;

    /** status 기본값 PENDING. 화면의 "전체"는 빈 문자열로 와서 상태 무관 전체(최신 500건). */
    @GetMapping
    public List<TraceRuleProposalView> getProposals(@RequestParam(required = false, defaultValue = "PENDING") String status) {
        return traceRuleService.getProposals(status.isBlank() ? null : status);
    }

    /** 고른 확인 대기 초안을 trace-rules.yml에 반영한다. 다음 점검부터 쓰인다. */
    @RequiresProgram("app-mng")
    @PostMapping("/apply")
    public int apply(@RequestBody TraceRuleProposalRequest request, Principal principal) throws Exception {
        return traceRuleService.apply(request.ids(), principal.getName());
    }

    @RequiresProgram("app-mng")
    @PostMapping("/dismiss")
    public int dismiss(@RequestBody TraceRuleProposalRequest request, Principal principal) {
        return traceRuleService.dismiss(request.ids(), principal.getName());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleInvalidRequest(IllegalArgumentException e) {
        return e.getMessage();
    }

    /** 그 밖의 예외 메시지에는 서버 경로 같은 내부 정보가 섞인다 — 원인은 서버 로그에 남기고 고정 문구만 준다. */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleError(Exception e) {
        log.error("추적 규칙 초안 API 실패", e);
        return "추적 규칙 초안 처리에 실패했습니다. 서버 로그를 확인해주세요.";
    }
}
