package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.domain.FixPlan;
import com.sjinc.cvemonitor.domain.ScanSnapshot;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget.CveFinding;
import com.sjinc.cvemonitor.dto.ai.FixPlanRequest;
import com.sjinc.cvemonitor.dto.ai.FixPlanResponse;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.FixPlanRepository;
import com.sjinc.cvemonitor.repository.ScanSnapshotRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class FixPlanService {

    private final ScanSnapshotRepository scanSnapshotRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FixPlanRepository fixPlanRepository;
    private final AppRepository appRepository;

    /** VulnerabilityService와 같은 기준. 이 등급 밖의 CVE들을 "낮은 등급 코멘트"로 요약해서 남긴다. */
    @Value("#{'${ai.assessment.severities:HIGH,CRITICAL}'.split(',')}")
    private List<String> aiAssessmentSeverities;

    /** stage-2(fix-plan) 배치가 폴링해서 가져갈, pom.xml 취합 수정이 필요한 앱 목록. */
    public List<AppFixPlanTarget> getPendingFixPlanTargets() {
        return scanSnapshotRepository.findPendingFixPlanTargets().stream()
                .map(this::toTarget)
                .filter(target -> !target.cveFindings().isEmpty()) // 취약 확정된 CVE가 하나도 없으면 취합할 게 없다.
                .toList();
    }

    private AppFixPlanTarget toTarget(ScanSnapshot snapshot) {
        Long appId = snapshot.getApp().getId();
        List<CveFinding> findings = vulnerabilityRepository.findByAppIdAndAiVulnerableTrue(appId).stream()
                .map(this::toCveFinding)
                .toList();

        return new AppFixPlanTarget(
                appId,
                snapshot.getApp().getSystemName(),
                snapshot.getPomXml(),
                snapshot.getDependencyTree(),
                findings
        );
    }

    private CveFinding toCveFinding(Vulnerability vulnerability) {
        return new CveFinding(
                vulnerability.getCveId(),
                vulnerability.getGroupId(),
                vulnerability.getArtifactId(),
                vulnerability.getVersion(),
                vulnerability.getAiFixedVersion(),
                vulnerability.getAiConfidence()
        );
    }

    /** fix-plan 배치가 취합 판단을 마친 뒤 그 결과를 저장할 때 호출. 앱당 최신 계획 하나만 유지한다. */
    @Transactional
    public void saveFixPlan(Long appId, FixPlanRequest request) {
        FixPlan plan = fixPlanRepository.findByAppId(appId)
                .orElseGet(() -> FixPlan.builder().app(appRepository.getReferenceById(appId)).build());

        plan.applyPlan(request.strategy(), request.pomXml(), request.unresolvedCves(), request.reasoning());
        plan.attachLowSeverityNote(buildLowSeverityNote(appId));
        fixPlanRepository.save(plan);

        scanSnapshotRepository.findByAppId(appId).ifPresent(snapshot -> {
            snapshot.markFixPlanGenerated();
            scanSnapshotRepository.save(snapshot);
        });
    }

    /**
     * AI 판단 대상(HIGH/CRITICAL)에서 빠진 LOW/MEDIUM CVE를 "artifact@version: CVE, CVE (N건)" 형태로
     * 아티팩트별로 묶어서 요약한다. AI가 만드는 게 아니라 DB 조회만으로 자바가 직접 만든다.
     */
    private String buildLowSeverityNote(Long appId) {
        List<Vulnerability> lowSeverity = vulnerabilityRepository.findByAppIdAndSeverityNotIn(appId, aiAssessmentSeverities);
        if (lowSeverity.isEmpty()) {
            return "";
        }

        Map<String, List<String>> cveIdsByArtifact = lowSeverity.stream()
                .collect(Collectors.groupingBy(
                        v -> v.getArtifactId() + "@" + v.getVersion(),
                        LinkedHashMap::new,
                        Collectors.mapping(Vulnerability::getCveId, Collectors.toList())));

        String detail = cveIdsByArtifact.entrySet().stream()
                .map(entry -> "  - %s: %s (%d건)".formatted(
                        entry.getKey(), String.join(", ", entry.getValue()), entry.getValue().size()))
                .collect(Collectors.joining("\n"));

        return "LOW/MEDIUM 등급 %d건은 AI 판단 대상(%s)에서 제외됨:\n%s".formatted(
                lowSeverity.size(), String.join("/", aiAssessmentSeverities), detail);
    }

    /** 사람이 화면/API로 완성된 fix-plan(수정된 pom.xml 등)을 조회할 때 사용. */
    public FixPlanResponse getFixPlan(Long appId) {
        FixPlan plan = fixPlanRepository.findByAppId(appId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "아직 fix-plan이 생성되지 않았습니다: appId=" + appId));

        return new FixPlanResponse(
                appId, plan.getStrategy(), plan.getStatus(), plan.getPomXml(),
                plan.getUnresolvedCves(), plan.getReasoning(), plan.getLowSeverityNote(), plan.getCreatedAt());
    }
}
