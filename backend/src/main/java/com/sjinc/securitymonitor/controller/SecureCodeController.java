package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.domain.SecureCodeScan;
import com.sjinc.securitymonitor.security.RequiresProgram;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeFindingCode;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeFindingView;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeScanRequest;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeScanResult;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusRequest;
import com.sjinc.securitymonitor.service.securecode.SecureCodeFindingService;
import com.sjinc.securitymonitor.exception.SecureCodeScanException;
import com.sjinc.securitymonitor.service.securecode.SecureCodeScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.security.Principal;
import java.util.List;

/**
 * 시큐어코딩 점검 API. 화면(코드 점검·코드 점검 결과)이 고정 메뉴라 라이브러리 스캔·취약점 관리와 같은 기준으로
 * 로그인만 요구한다 — 그래서 {@code @RequiresProgram}을 붙이지 않는다. 처리여부를 누가 바꿨는지는 statusChangedBy로 남는다.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/secure-code")
public class SecureCodeController {

    private final SecureCodeScanService scanService;
    private final SecureCodeFindingService findingService;

    /** 화면의 "점검" 버튼. clone·Semgrep이 끝날 때까지 기다린다(라이브러리 스캔과 같다). */
    @PostMapping("/scan")
    public SecureCodeScanResult scan(@RequestBody SecureCodeScanRequest request, Principal principal) throws Exception {
        if (request.appId() == null) {
            throw new IllegalArgumentException("점검할 앱을 선택하세요.");
        }
        return scanService.scan(request.appId(), principal != null ? principal.getName() : null);
    }

    /**
     * 소스 업로드 앱의 "업로드 점검". zip을 받아 풀고 점검한다(끝날 때까지 기다린다).
     * 점검 버튼과 달리 앱 관리 권한이 필요하다 — 올린 소스가 그 앱의 점검 결과를 대신하므로, 엉뚱한 소스를 올리면 기존 탐지가 "해결"로 바뀐다.
     */
    @RequiresProgram("app-mng")
    @PostMapping(value = "/scan-upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public SecureCodeScanResult scanUpload(@RequestParam Long appId, @RequestParam("file") MultipartFile file,
                                           Principal principal) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("올릴 zip 파일을 선택하세요.");
        }
        try (InputStream content = file.getInputStream()) {
            return scanService.scanUpload(appId, principal != null ? principal.getName() : null,
                    file.getOriginalFilename(), content);
        }
    }

    /** appId를 주지 않으면 전체 앱. 최신순으로 최대 500건. */
    @GetMapping("/scans")
    public List<SecureCodeScan> getScans(@RequestParam(required = false) Long appId) {
        return scanService.getHistories(appId);
    }

    /** status 기본값 OPEN. 화면의 "전체"는 빈 문자열로 와서 상태 무관 전체를 본다(취약점 관리와 같은 규칙). */
    @GetMapping("/findings")
    public List<SecureCodeFindingView> getFindings(@RequestParam(required = false) Long appId,
                                                   @RequestParam(required = false, defaultValue = "OPEN") String status) {
        return findingService.getFindings(appId, status.isBlank() ? null : status);
    }

    /** 상세보기를 열 때 한 건의 코드(조각·연계 추적 근거 코드)를 받는다. 목록에는 코드를 넣지 않는다. */
    @GetMapping("/findings/{id}/code")
    public SecureCodeFindingCode getFindingCode(@PathVariable Long id) {
        return findingService.getCode(id);
    }

    @PostMapping("/findings/status")
    public void changeStatuses(@RequestBody List<SecureCodeStatusRequest> requests, Principal principal) {
        findingService.changeStatuses(requests, principal.getName());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleInvalidRequest(IllegalArgumentException e) {
        return e.getMessage();
    }

    /** 문구를 우리가 정한 실패(설치 안 됨·시간 초과·규칙 폴더 문제)는 그대로 보여준다. 다른 점검이 도는 중이면 409. */
    @ExceptionHandler(SecureCodeScanException.class)
    public ResponseEntity<String> handleScanFailure(SecureCodeScanException e) {
        if (e.isBusy()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        }
        log.error("코드 점검 실패", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
    }

    /** 그 밖의 예외 메시지에는 서버 임시 경로 같은 내부 정보가 섞인다 — 원인은 서버 로그에 남기고 고정 문구만 준다. */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleError(Exception e) {
        log.error("코드 점검 API 실패", e);
        return "코드 점검에 실패했습니다. 서버 로그를 확인해주세요.";
    }
}
