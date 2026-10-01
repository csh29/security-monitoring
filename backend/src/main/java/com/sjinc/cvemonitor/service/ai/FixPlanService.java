package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.domain.FixPlan;
import com.sjinc.cvemonitor.domain.FixPlanChange;
import com.sjinc.cvemonitor.domain.ScanSnapshot;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget;
import com.sjinc.cvemonitor.dto.ai.AppFixPlanTarget.CveFinding;
import com.sjinc.cvemonitor.dto.ai.FixPlanRequest;
import com.sjinc.cvemonitor.dto.ai.FixPlanResponse;
import com.sjinc.cvemonitor.dto.ai.UpgradeImpactView;
import com.sjinc.cvemonitor.dto.ai.CodeUsageView;
import com.sjinc.cvemonitor.dto.scan.SourceUsage;
import com.sjinc.cvemonitor.domain.UpgradeImpact;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.FixPlanRepository;
import com.sjinc.cvemonitor.repository.ScanSnapshotRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import com.sjinc.cvemonitor.service.maven.MavenDependencyExtractor;
import com.sjinc.cvemonitor.service.maven.VersionJumpClassifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class FixPlanService {

    private final ScanSnapshotRepository scanSnapshotRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FixPlanRepository fixPlanRepository;
    private final AppRepository appRepository;
    private final MavenDependencyExtractor mavenDependencyExtractor;
    private final UpgradeImpactService upgradeImpactService;
    private final ObjectMapper objectMapper;

    /** fix-plan 변경 항목의 via 허용값. 파이썬 FIX_PLAN_SCHEMA의 enum과 같아야 한다. */
    private static final Set<String> CHANGE_VIA = Set.of("PARENT", "BOM", "PROPERTY", "DIRECT");
    private static final Pattern COORDINATE = Pattern.compile("[^:\\s]+:[^:\\s]+");

    /**
     * VulnerabilityService와 같은 기준. fix-plan은 이 등급의 취약 확정 CVE만 다루고, 이 등급 밖의 CVE들은
     * "낮은 등급 코멘트"로 요약해서 남긴다.
     */
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
        List<Vulnerability> vulnerabilities = vulnerabilityRepository.findConfirmedVulnerable(appId, "OPEN", aiAssessmentSeverities);

        Set<String> targetCoordinates = vulnerabilities.stream()
                .map(v -> v.getGroupId() + ":" + v.getArtifactId())
                .collect(Collectors.toSet());

        String dependencyTree = snapshot.getDependencyTree();
        // AI가 dependency:tree 텍스트를 눈으로 다시 훑어 경로를 재구성하다가 이름이 비슷한 형제
        // 노드를 혼동하는 실수(예: spring-security-config vs spring-security-web)를 구조적으로
        // 없애기 위해, 각 CVE 아티팩트의 조상 체인을 자바에서 미리 계산해서 CveFinding에 실어 보낸다.
        Map<String, List<String>> chains = mavenDependencyExtractor.resolveChains(dependencyTree, targetCoordinates);
        // CVE와 무관한 나머지 서브트리까지 통째로 프롬프트에 넣지 않도록, 해당 아티팩트로 가는
        // 경로만 추린다. 매칭이 하나도 없으면(파싱 실패 등) pruneToPaths가 원문을 그대로 돌려준다.
        String prunedDependencyTree = mavenDependencyExtractor.pruneToPaths(dependencyTree, targetCoordinates);

        List<CveFinding> findings = vulnerabilities.stream()
                .map(v -> toCveFinding(v, chains))
                .toList();

        return new AppFixPlanTarget(
                appId,
                snapshot.getApp().getSystemName(),
                snapshot.getPomXml(),
                prunedDependencyTree,
                findings
        );
    }

    private CveFinding toCveFinding(Vulnerability vulnerability, Map<String, List<String>> chains) {
        String coordinate = vulnerability.getGroupId() + ":" + vulnerability.getArtifactId();
        List<String> chain = chains.get(coordinate);
        // 체인 크기가 1이면(자기 자신뿐) 최상위 직접 의존성이라는 뜻이라 경로를 따로 안 붙인다.
        String dependencyPath = (chain != null && chain.size() > 1) ? String.join(" -> ", chain) : null;

        return new CveFinding(
                vulnerability.getCveId(),
                vulnerability.getGroupId(),
                vulnerability.getArtifactId(),
                vulnerability.getVersion(),
                vulnerability.getAiFixedVersion(),
                vulnerability.getAiConfidence(),
                vulnerability.getBroughtInBy(),
                dependencyPath
        );
    }

    /** fix-plan 배치가 취합 판단을 마친 뒤 그 결과를 저장할 때 호출. 앱당 최신 계획 하나만 유지한다. */
    @Transactional
    public void saveFixPlan(Long appId, FixPlanRequest request) {
        FixPlan plan = fixPlanRepository.findByAppId(appId)
                .orElseGet(() -> FixPlan.builder().app(appRepository.getReferenceById(appId)).build());

        plan.applyPlan(request.strategy(), request.pomXml(), request.unresolvedCves(), request.reasoning());
        plan.replaceChanges(toChanges(plan, request.changes()));
        plan.attachLowSeverityNote(buildLowSeverityNote(appId));
        fixPlanRepository.save(plan);

        scanSnapshotRepository.findByAppId(appId).ifPresent(snapshot -> {
            snapshot.markFixPlanGenerated();
            scanSnapshotRepository.save(snapshot);
        });
    }

    /**
     * AI가 낸 변경 목록을 저장할 엔티티로 바꾸고 점프 폭을 붙인다. 형식이 틀린 항목은 그 항목만 버린다 — 수정안
     * 전체(pom.xml)는 멀쩡한데 변경 목록 한 줄 때문에 저장을 거절하면, 비싼 fix-plan 생성을 통째로 다시 돌려야 한다.
     * 버린 건수는 로그로 남긴다.
     */
    private List<FixPlanChange> toChanges(FixPlan plan, List<FixPlanRequest.Change> requested) {
        List<FixPlanRequest.Change> valid = validChanges(requested);
        int dropped = (requested == null ? 0 : requested.size()) - valid.size();
        if (dropped > 0) {
            log.warn("appId={} fix-plan 변경 목록 중 형식이 틀린 {}건을 버렸습니다.", plan.getApp().getId(), dropped);
        }
        List<FixPlanChange> changes = new ArrayList<>();
        for (int i = 0; i < valid.size(); i++) {
            FixPlanRequest.Change change = valid.get(i);
            changes.add(FixPlanChange.builder()
                    .fixPlan(plan)
                    .sortOrder(i)
                    .coordinate(change.coordinate().trim())
                    .propertyName(isBlank(change.propertyName()) ? null : change.propertyName().trim())
                    .fromVersion(change.fromVersion().trim())
                    .toVersion(change.toVersion().trim())
                    .via(change.via())
                    .jump(VersionJumpClassifier.classify(change.fromVersion().trim(), change.toVersion().trim()))
                    .build());
        }
        return changes;
    }

    /** 좌표가 groupId:artifactId 모양이고, 버전 두 개가 있고, via가 정해진 값인 항목만 남긴다. */
    static List<FixPlanRequest.Change> validChanges(List<FixPlanRequest.Change> requested) {
        if (requested == null) {
            return List.of();
        }
        return requested.stream()
                .filter(Objects::nonNull)
                .filter(c -> c.coordinate() != null && COORDINATE.matcher(c.coordinate().trim()).matches())
                .filter(c -> !isBlank(c.fromVersion()) && !isBlank(c.toVersion()))
                .filter(c -> CHANGE_VIA.contains(c.via()))
                .toList();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * AI 판단·fix-plan 대상(HIGH/CRITICAL)에서 빠진 LOW/MEDIUM CVE를 "artifact@version: CVE, CVE (N건)" 형태로
     * 아티팩트별로 묶어서 요약한다. AI가 만드는 게 아니라 DB 조회만으로 자바가 직접 만든다.
     */
    private String buildLowSeverityNote(Long appId) {
        List<Vulnerability> lowSeverity = vulnerabilityRepository.findOutOfAssessmentScope(appId, aiAssessmentSeverities, "OPEN");
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

        return "LOW/MEDIUM 등급 %d건은 AI 판단·fix-plan 대상(%s)에서 제외됨:\n%s".formatted(
                lowSeverity.size(), String.join("/", aiAssessmentSeverities), detail);
    }

    private static CodeUsageView codeUsage(UpgradeImpactView impact, SourceUsage sourceUsage) {
        if (impact == null || !UpgradeImpact.ANALYZED.equals(impact.status()) || impact.breakingChanges().isEmpty()) {
            return null; // 대조할 breaking change가 없다
        }
        return CodeUsageMatcher.match(impact.breakingChanges(), sourceUsage);
    }

    /** 스냅샷의 소스 사용 목록. 없거나 읽을 수 없으면 null — 대조 결과가 "판단 불가"가 된다. */
    private SourceUsage loadSourceUsage(Long appId) {
        String json = scanSnapshotRepository.findByAppId(appId).map(ScanSnapshot::getSourceUsageJson).orElse(null);
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(json, SourceUsage.class);
        } catch (Exception e) {
            log.warn("appId={} 소스 사용 목록을 읽지 못했습니다: {}", appId, e.getMessage());
            return null;
        }
    }

    /** 사람이 화면/API로 완성된 fix-plan(수정된 pom.xml 등)을 조회할 때 사용. */
    @Transactional(readOnly = true) // changes는 지연 로딩이라 트랜잭션 안에서 읽어야 한다
    public FixPlanResponse getFixPlan(Long appId) {
        FixPlan plan = fixPlanRepository.findByAppId(appId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "아직 fix-plan이 생성되지 않았습니다: appId=" + appId));

        Map<String, UpgradeImpactView> impacts = upgradeImpactService.findImpacts(plan.getChanges());
        SourceUsage sourceUsage = loadSourceUsage(appId);
        List<FixPlanResponse.Change> changes = plan.getChanges().stream()
                .map(c -> {
                    UpgradeImpactView impact = impacts.get(UpgradeImpactService.key(c.getCoordinate(), c.getFromVersion(), c.getToVersion()));
                    return new FixPlanResponse.Change(c.getCoordinate(), c.getPropertyName(), c.getFromVersion(),
                            c.getToVersion(), c.getVia(), c.getJump(), impact, codeUsage(impact, sourceUsage));
                })
                .toList();
        return new FixPlanResponse(
                appId, plan.getStrategy(), plan.getStatus(), plan.getPomXml(),
                plan.getUnresolvedCves(), plan.getReasoning(), plan.getLowSeverityNote(), plan.getCreatedAt(), changes);
    }
}
