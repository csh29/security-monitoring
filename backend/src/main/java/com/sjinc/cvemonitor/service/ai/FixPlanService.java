package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.domain.FixPlan;
import com.sjinc.cvemonitor.domain.ScanSnapshot;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget.CveFinding;
import com.sjinc.cvemonitor.dto.ai.FixPlanRequest;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.FixPlanRepository;
import com.sjinc.cvemonitor.repository.ScanSnapshotRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class FixPlanService {

    private final ScanSnapshotRepository scanSnapshotRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FixPlanRepository fixPlanRepository;
    private final AppRepository appRepository;

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
        fixPlanRepository.save(plan);

        scanSnapshotRepository.findByAppId(appId).ifPresent(snapshot -> {
            snapshot.markFixPlanGenerated();
            scanSnapshotRepository.save(snapshot);
        });
    }
}
