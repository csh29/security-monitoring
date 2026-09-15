package com.sjinc.cvemonitor.service.scan;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.domain.MavenDependency;
import com.sjinc.cvemonitor.domain.ScanSnapshot;
import com.sjinc.cvemonitor.dto.osv.OsvBatchResultItem;
import com.sjinc.cvemonitor.dto.osv.OsvVulnRef;
import com.sjinc.cvemonitor.dto.scan.ScanResult;
import com.sjinc.cvemonitor.dto.scan.ScanResult.DependencyFinding;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.repository.ScanSnapshotRepository;
import com.sjinc.cvemonitor.service.ai.AiAssessmentTriggerService;
import com.sjinc.cvemonitor.service.maven.MavenDependencyExtractor;
import com.sjinc.cvemonitor.service.maven.MavenDependencyExtractor.DependencyTreeResult;
import com.sjinc.cvemonitor.dto.osv.OsvVulnDetail;
import com.sjinc.cvemonitor.service.osv.OsvClient;
import com.sjinc.cvemonitor.service.git.GitCloneService;
import com.sjinc.cvemonitor.service.vulnerability.VulnerabilityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanOrchestrationService {

    private final GitCloneService gitCloneService;
    private final MavenDependencyExtractor dependencyExtractor;
    private final OsvClient osvClient;
    private final VulnerabilityService vulnerabilityService;
    private final AppRepository appRepository;
    private final ScanSnapshotRepository scanSnapshotRepository;
    private final AiAssessmentTriggerService aiAssessmentTriggerService;

    @Value("${git.access.token}")
    private String gitAccessToken;

    @Value("${git.user.name}")
    private String gitUserName;

    @Value("${maven.home}")
    private String mavenHome;

    public ScanResult scanRepository(String repoUrl, String branch) throws Exception {
        App app = appRepository.findByRepoUrlAndBranch(repoUrl, branch).orElse(null);
        String systemName = app != null ? app.getSystemName() : null;
        Long appId = app != null ? app.getId() : null;

        File projectDir = gitCloneService.cloneRepository(repoUrl, branch, gitUserName, gitAccessToken);
        try {
            List<MavenDependency> dependencies = dependencyExtractor.extract(projectDir, mavenHome);
            List<OsvBatchResultItem> results = osvClient.queryBatch(dependencies).getResults();

            List<DependencyFinding> findings = new ArrayList<>();
            for (int i = 0; i < results.size(); i++) {
                MavenDependency dependency = dependencies.get(i);
                List<OsvVulnRef> vulnRefs = results.get(i).getVulns();
                if (vulnRefs == null || vulnRefs.isEmpty()) continue;

                Map<String, OsvVulnDetail> dedupedByCve = new LinkedHashMap<>();
                for (OsvVulnRef ref : vulnRefs) {
                    OsvVulnDetail detail = osvClient.getVulnDetail(ref.getId());
                    dedupedByCve.putIfAbsent(extractCveOrId(detail), detail);
                }

                dedupedByCve.forEach((identifier, detail) -> findings.add(new DependencyFinding(
                        dependency.groupId(), dependency.artifactId(), dependency.version(),
                        identifier, detail.getSummary(), joinFixedVersions(detail))));
            }

            // Vulnerability 한 행에 아티팩트 하나만 담기므로, 이 앱 안에서 같은 CVE를 유발한 의존성이
            // 여럿이면(예: 같은 CVE가 서로 다른 두 아티팩트에 걸림) 그중 하나만 대표로 남긴다.
            // (app_id, cveId) 유니크는 "같은 앱"이라는 범위만 보장할 뿐, 이 다중 아티팩트 축약과는 무관하다.
            Collection<DependencyFinding> cveFindings = findings.stream()
                    .filter(finding -> isCveId(finding.identifier()))
                    .collect(Collectors.toMap(
                            DependencyFinding::identifier,
                            finding -> finding,
                            (first, second) -> first,
                            LinkedHashMap::new))
                    .values();

            log.info("동기화 대상 CVE ID: {}", cveFindings.stream()
                    .map(DependencyFinding::identifier)
                    .collect(Collectors.joining(", ")));

            // CVE 건수만큼 mvn dependency:tree를 반복 실행하지 않도록, 트리를 한 번만 떠서 맵으로 미리 만들어둔다.
            DependencyTreeResult treeResult = cveFindings.isEmpty()
                    ? new DependencyTreeResult(Map.of(), "")
                    : dependencyExtractor.buildTopLevelCauseMap(projectDir, mavenHome);
            Map<String, String> topLevelCauseByCoordinate = treeResult.topLevelCauseByCoordinate();

            cveFindings.forEach(finding -> {
                String coordinate = finding.groupId() + ":" + finding.artifactId();
                String broughtInBy = topLevelCauseByCoordinate.get(coordinate);
                vulnerabilityService.syncCveById(
                        finding.identifier(), appId, finding.groupId(), finding.artifactId(), finding.version(), broughtInBy,
                        finding.knownFixedVersions());
            });

            if (app != null) {
                // 라이브러리 삭제/업그레이드로 이번 스캔엔 안 걸린 기존 OPEN 건을 RESOLVED로 표시한다.
                // cveFindings가 비어있어도(전부 해소된 경우) 실행해야 하므로 이 블록 밖에서 처리한다.
                Set<String> currentCveIds = cveFindings.stream()
                        .map(DependencyFinding::identifier)
                        .collect(Collectors.toSet());
                vulnerabilityService.resolveMissingVulnerabilities(appId, currentCveIds);
            }

            if (!cveFindings.isEmpty()) {
                // fix-plan 배치가 나중에 pom.xml/tree를 참고할 수 있도록, clone 디렉터리를 지우기 전에 스냅샷으로 남겨둔다.
                if (app != null) {
                    String pomXml = Files.readString(new File(projectDir, "pom.xml").toPath());
                    ScanSnapshot snapshot = scanSnapshotRepository.findByAppId(appId)
                            .orElseGet(() -> ScanSnapshot.builder().app(app).build());
                    snapshot.updateSnapshot(pomXml, treeResult.rawText());
                    scanSnapshotRepository.save(snapshot);
                }

                // 새로 저장된 CVE가 있을 때만 AI 판단 배치를 깨운다.
                aiAssessmentTriggerService.triggerAsync();
            }

            return new ScanResult(repoUrl, branch, systemName, dependencies.size(), cveFindings.size(), findings);
        } finally {
            gitCloneService.cleanup(projectDir);
        }
    }

    private String joinFixedVersions(OsvVulnDetail detail) {
        List<String> fixedVersions = detail.getFixedVersions();
        return fixedVersions.isEmpty() ? null : String.join(", ", fixedVersions);
    }

    private String extractCveOrId(OsvVulnDetail detail) {
        if (detail.getAliases() == null) return detail.getId();
        return detail.getAliases().stream()
                .filter(a -> a.startsWith("CVE-"))
                .findFirst()
                .orElse(detail.getId());
    }

    /** GHSA 등 CVE 별칭이 없는 식별자는 NVD에서 조회할 수 없으므로 제외한다. */
    private boolean isCveId(String identifier) {
        return identifier != null && identifier.startsWith("CVE-");
    }
}