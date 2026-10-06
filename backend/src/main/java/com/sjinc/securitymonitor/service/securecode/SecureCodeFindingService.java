package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.domain.SeverityOrder;
import com.sjinc.securitymonitor.dto.securecode.DetectedFinding;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeDashboard;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusCount;
import com.sjinc.securitymonitor.dto.vulnerability.AppVulnerabilityCount;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeApplyResult;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeFindingView;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusRequest;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** 코드 점검 탐지(SecureCodeFinding)의 저장·조회·처리여부 변경. */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecureCodeFindingService {

    private final SecureCodeFindingRepository findingRepository;
    private final AppRepository appRepository;

    /** 이번 점검 결과를 기존 탐지와 맞춰 저장한다. 순수 DB 작업만 하므로 트랜잭션 하나로 묶는다(일부만 반영되지 않게). */
    @Transactional
    public SecureCodeApplyResult applyScan(Long appId, List<DetectedFinding> detected, Set<String> failedFiles,
                                           Set<String> activeRuleIds) {
        SecureCodeReconciler.Result result = SecureCodeReconciler.reconcile(appId, findingRepository.findByAppId(appId),
                detected, failedFiles, activeRuleIds, LocalDateTime.now());
        findingRepository.saveAll(result.toSave());
        return new SecureCodeApplyResult(result.newCount(), result.resolvedCount());
    }

    /** 홈 대시보드의 시큐어코딩 구역. */
    @Transactional(readOnly = true)
    public SecureCodeDashboard getDashboard(int topApps) {
        return summarize(findingRepository.countByStatusAndSeverity(),
                findingRepository.countOpenByApp().stream().limit(topApps).toList());
    }

    /**
     * 비율 계산. 탐지가 하나도 없으면 비율 대신 "점검 전/탐지 없음"을 보이도록 scanned=false로 넘긴다 — 라이브러리 쪽처럼
     * 처리율 100%로 보이면 아직 점검을 안 한 상태가 "다 고쳤다"로 읽힌다.
     */
    static SecureCodeDashboard summarize(List<SecureCodeStatusCount> counts, List<AppVulnerabilityCount> topApps) {
        long total = 0, open = 0, openHigh = 0;
        for (SecureCodeStatusCount c : counts) {
            total += c.count();
            if (SecureCodeFinding.OPEN.equals(c.status())) {
                open += c.count();
                if ("HIGH".equals(c.severity())) openHigh += c.count();
            }
        }
        long openHighRate = open == 0 ? 0 : Math.round(openHigh * 100.0 / open);
        long handledRate = total == 0 ? 0 : Math.round((total - open) * 100.0 / total);
        return new SecureCodeDashboard(open, openHighRate, handledRate, total > 0, topApps);
    }

    /** status가 null이면 처리여부 무관 전체. 앱 관리에서 지워진 앱의 행은 뺀다(FK가 없어 남아 있을 수 있다). */
    @Transactional(readOnly = true)
    public List<SecureCodeFindingView> getFindings(Long appId, String status) {
        Map<Long, String> systemNames = appRepository.findAll().stream()
                .collect(Collectors.toMap(App::getId, App::getSystemName));
        // 심각도 높은 것부터. 같은 등급 안에서는 쿼리 순서(앱·파일·줄)를 그대로 둔다 — sorted는 안정 정렬이다.
        return findingRepository.search(appId, status).stream()
                .filter(finding -> systemNames.containsKey(finding.getAppId()))
                .sorted(Comparator.comparing(SecureCodeFinding::getSeverity, SeverityOrder.HIGH_FIRST))
                .map(finding -> SecureCodeFindingView.of(finding, systemNames.get(finding.getAppId())))
                .toList();
    }

    /**
     * 화면에서 바꾼 처리여부·비고를 저장한다. 실제로 달라진 항목만 반영한다 — 비고만 고친 행에 처리여부까지 다시 적용하면
     * 스캔이 만든 상태가 수동 처리로 굳는다(VulnerabilityService.changeStatuses와 같은 규칙). 한 건이라도 잘못되면 전체를 되돌린다.
     */
    @Transactional
    public void changeStatuses(List<SecureCodeStatusRequest> requests, String changedBy) {
        LocalDateTime now = LocalDateTime.now();
        for (SecureCodeStatusRequest request : requests) {
            SecureCodeFinding finding = findingRepository.findById(request.id())
                    .orElseThrow(() -> new IllegalArgumentException("탐지 건을 찾을 수 없습니다: id=" + request.id()));
            if (!Objects.equals(finding.getStatus(), request.status())) {
                finding.changeStatusManually(request.status(), changedBy, now);
            }
            String remark = (request.remark() == null || request.remark().isBlank()) ? null : request.remark();
            if (!Objects.equals(finding.getRemark(), remark)) {
                finding.changeRemark(remark, changedBy);
            }
        }
        log.info("{}이(가) 코드 점검 탐지 {}건의 처리여부/비고를 변경", changedBy, requests.size());
    }
}
