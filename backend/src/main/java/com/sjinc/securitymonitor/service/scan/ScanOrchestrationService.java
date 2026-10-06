package com.sjinc.securitymonitor.service.scan;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.MavenDependency;
import com.sjinc.securitymonitor.domain.ScanHistory;
import com.sjinc.securitymonitor.domain.ScanSnapshot;
import com.sjinc.securitymonitor.dto.osv.OsvBatchResultItem;
import com.sjinc.securitymonitor.dto.osv.OsvVulnRef;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.dto.scan.ScanResult;
import com.sjinc.securitymonitor.dto.scan.SourceUsage;
import com.sjinc.securitymonitor.dto.scan.ScanResult.DependencyFinding;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.ScanSnapshotRepository;
import com.sjinc.securitymonitor.service.ai.AiAssessmentTriggerService;
import com.sjinc.securitymonitor.service.ai.CveSummaryService;
import com.sjinc.securitymonitor.service.ai.FixPlanService;
import com.sjinc.securitymonitor.service.ai.UpgradeImpactService;
import com.sjinc.securitymonitor.service.maven.MavenDependencyExtractor;
import com.sjinc.securitymonitor.service.maven.MavenDependencyExtractor.DependencyTreeResult;
import com.sjinc.securitymonitor.dto.osv.OsvVulnDetail;
import com.sjinc.securitymonitor.service.osv.OsvClient;
import com.sjinc.securitymonitor.service.git.GitCloneService;
import com.sjinc.securitymonitor.service.vulnerability.VulnerabilityService;
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
    private final FixPlanService fixPlanService;
    private final CveSummaryService cveSummaryService;
    private final ScanHistoryService scanHistoryService;
    private final UpgradeImpactService upgradeImpactService;
    private final SourceUsageExtractor sourceUsageExtractor;
    private final ObjectMapper objectMapper;

    @Value("${git.access.token}")
    private String gitAccessToken;

    @Value("${git.user.name}")
    private String gitUserName;

    @Value("${maven.home}")
    private String mavenHome;

    /** @param requestedBy 스캔을 실행한 로그인 아이디(스캔 이력에 남긴다) */
    public ScanResult scanRepository(String repoUrl, String branch, String requestedBy) throws Exception {
        // repoUrl/branch를 검증 없이 그대로 clone하면, 앱 관리에 등록되지 않은 임의 URL도 스캔
        // 대상이 될 수 있다 — GitLab PAT를 공격자 서버로 그대로 보내거나(자격증명 유출), 공격자가
        // 만든 pom.xml의 <repositories>/build extension을 Maven이 그대로 실행하거나, repoUrl에
        // 내부망 주소·file:// 경로를 넣어 SSRF/로컬 파일 접근에 악용될 수 있다. 앱 관리("app-mng"
        // 권한이 있어야 등록 가능)에 이미 등록된 조합만 스캔을 허용해서 이 경로를 원천 차단한다.
        App app = appRepository.findByRepoUrlAndBranch(repoUrl, branch)
                .orElseThrow(() -> new IllegalArgumentException(
                        "앱 관리에 등록되지 않은 저장소/브랜치입니다: " + repoUrl + " (" + branch + ")"));

        // 등록 검증을 통과한 스캔만 이력에 남긴다 — 미등록 저장소 요청은 앱이 없어 이력의 주인이 없다.
        ScanHistory history = scanHistoryService.start(app, requestedBy);
        try {
            return scan(app, history);
        } catch (Exception e) {
            scanHistoryService.fail(history, e);
            throw e;
        }
    }

    private ScanResult scan(App app, ScanHistory history) throws Exception {
        String repoUrl = app.getRepoUrl();
        String branch = app.getBranch();
        String systemName = app.getSystemName();
        Long appId = app.getId();
        // 신규 건수는 "스캔 전엔 OPEN이 아니었는데 스캔 후 OPEN"으로 센다. 저장(syncCveById)이 upsert라
        // 저장 결과만 봐서는 새 행인지 기존 행 갱신인지 알 수 없어서, 전후 OPEN 키 집합을 비교한다.
        Set<String> openKeysBefore = vulnerabilityService.getOpenKeys(appId);

        File projectDir = gitCloneService.cloneRepository(repoUrl, branch, gitUserName, gitAccessToken);
        try {
            List<MavenDependency> dependencies = dependencyExtractor.extract(projectDir, mavenHome);
            List<OsvBatchResultItem> results = osvClient.queryBatch(dependencies).getResults();

            List<DependencyFinding> findings = new ArrayList<>();
            // upsertEntity에서 NVD 구조화 범위가 없을 때 OSV 구조화 범위로 한 번 더 확인할 수 있도록,
            // 스캔 때 이미 받아온 OsvVulnDetail을 (cveId, groupId, artifactId) 키로 보관해둔다 —
            // 같은 상세를 얻으려고 OSV를 또 호출하지 않기 위함이다.
            Map<String, OsvVulnDetail> detailByKey = new LinkedHashMap<>();
            for (int i = 0; i < results.size(); i++) {
                MavenDependency dependency = dependencies.get(i);
                List<OsvVulnRef> vulnRefs = results.get(i).getVulns();
                if (vulnRefs == null || vulnRefs.isEmpty()) continue;

                Map<String, OsvVulnDetail> dedupedByCve = new LinkedHashMap<>();
                for (OsvVulnRef ref : vulnRefs) {
                    OsvVulnDetail detail = osvClient.getVulnDetail(ref.getId());
                    dedupedByCve.putIfAbsent(extractCveOrId(detail), detail);
                }

                dedupedByCve.forEach((identifier, detail) -> {
                    findings.add(new DependencyFinding(
                            dependency.groupId(), dependency.artifactId(), dependency.version(),
                            identifier, detail.getSummary(), joinFixedVersions(detail)));
                    detailByKey.put(identifier + "|" + dependency.groupId() + ":" + dependency.artifactId(), detail);
                });
            }

            // 같은 CVE가 서로 다른 두 아티팩트에 걸리는 경우가 실제로 있다(예: micrometer-core와
            // micrometer-registry-prometheus가 같은 CVE-2026-40984에 걸림). 예전엔 CVE ID만으로
            // 대표 하나만 남기고 나머지 아티팩트를 통째로 버렸는데, 그러면 그 아티팩트의 실제 취약
            // 버전이 Vulnerability 테이블에 아예 안 남아서 fix-plan이 그 라이브러리 패치를 영원히
            // 모른다 — 실제로 겪은 버그다. (cveId, groupId, artifactId) 조합 단위로 남긴다
            // (app_id, cve_id, group_id, artifact_id) 복합 유니크와 정확히 같은 기준이다.
            Collection<DependencyFinding> cveFindings = findings.stream()
                    .filter(finding -> isCveId(finding.identifier()))
                    .collect(Collectors.toMap(
                            finding -> finding.identifier() + "|" + finding.groupId() + ":" + finding.artifactId(),
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

            // NVD 조회는 외부 API라 한 건이 실패할 수 있다(호출 한도 초과, 일시 장애).
            // 예전엔 여기에 예외 처리가 없어서 한 건만 실패해도 스캔 전체가 500으로 죽었다 — 그것도
            // clone과 Maven 두 번을 이미 다 돌린 뒤에, 가장 비싼 작업을 버리는 시점에서. 게다가
            // syncCveById는 건별 트랜잭션이라 앞쪽 CVE는 이미 저장된 채로 아래 해소 처리
            // (resolveMissingVulnerabilities)만 실행되지 않아 DB가 어정쩡한 상태로 남았다.
            // 한 건 실패는 그 건만 건너뛰고, 실패 건수는 응답으로 올려 사람이 알 수 있게 한다.
            List<String> failedCveIds = new ArrayList<>();
            for (DependencyFinding finding : cveFindings) {
                String coordinate = finding.groupId() + ":" + finding.artifactId();
                String broughtInBy = topLevelCauseByCoordinate.get(coordinate);
                String key = finding.identifier() + "|" + finding.groupId() + ":" + finding.artifactId();
                try {
                    vulnerabilityService.syncCveById(
                            finding.identifier(), appId, finding.groupId(), finding.artifactId(), finding.version(), broughtInBy,
                            finding.knownFixedVersions(), detailByKey.get(key));
                } catch (Exception e) {
                    failedCveIds.add(finding.identifier());
                    log.warn("[{}] {}:{} 동기화 실패, 이 건만 건너뜁니다: {}",
                            finding.identifier(), finding.groupId(), finding.artifactId(), e.toString());
                }
            }
            if (!failedCveIds.isEmpty()) {
                log.warn("NVD 동기화 실패 {}건(스캔은 계속 진행됨): {}",
                        failedCveIds.size(), String.join(", ", failedCveIds));
            }

            // 라이브러리 삭제/업그레이드로 이번 스캔엔 안 걸린 기존 OPEN 건을 RESOLVED로 표시한다.
            // cveFindings가 비어있어도(전부 해소된 경우) 실행해야 하므로 이 블록 밖에서 처리한다.
            // CVE ID만으로 비교하면 안 된다 — 같은 CVE가 여러 아티팩트에 걸린 경우, 한쪽
            // 아티팩트가 해소돼도 다른 아티팩트가 여전히 걸려있으면(같은 CVE ID) 잘못 RESOLVED
            // 처리될 수 있다. (cveId, groupId, artifactId) 조합 단위로 비교해야 정확하다.
            Set<String> currentKeys = cveFindings.stream()
                    .map(f -> f.identifier() + "|" + f.groupId() + ":" + f.artifactId())
                    .collect(Collectors.toSet());
            int resolvedCount = vulnerabilityService.resolveMissingVulnerabilities(appId, currentKeys);

            if (!cveFindings.isEmpty()) {
                // fix-plan 배치가 나중에 pom.xml/tree를 참고할 수 있도록, clone 디렉터리를 지우기 전에 스냅샷으로 남겨둔다.
                String pomXml = Files.readString(new File(projectDir, "pom.xml").toPath());
                ScanSnapshot snapshot = scanSnapshotRepository.findByAppId(appId)
                        .orElseGet(() -> ScanSnapshot.builder().app(app).build());
                snapshot.updateSnapshot(pomXml, treeResult.rawText(), extractSourceUsage(projectDir, systemName));
                scanSnapshotRepository.save(snapshot);
            }

            ScanResult result = new ScanResult(repoUrl, branch, systemName, dependencies.size(), cveFindings.size(),
                    failedCveIds.size(), findings);
            int newCount = ScanHistoryService.countNewlyOpened(openKeysBefore, vulnerabilityService.getOpenKeys(appId));
            scanHistoryService.succeed(history, result, newCount, resolvedCount);

            // 스캔 결과를 다 저장한 뒤(스냅샷 포함 — fix-plan 대상 판단에 필요) AI 판단 배치를 깨운다.
            triggerAiAssessmentIfNeeded();

            return result;
        } finally {
            gitCloneService.cleanup(projectDir);
        }
    }

    /**
     * 파이썬 AI 배치(ai/vuln_assessor.py)가 할 일이 있을 때만 백그라운드로 띄운다.
     *
     * <p>"새로 저장된 CVE가 있는가"가 아니라 배치가 실제로 가져갈 대기열 두 개를 기준으로 본다 —
     * 새 CVE라도 결정론적 자동판정으로 끝나면 AI가 볼 게 없고(괜히 띄우면 할 일 없이 뜨는 프로세스),
     * 반대로 새 CVE가 없어도 이번 스캔이 스냅샷을 갱신했으면 fix-plan이 다시 대기 상태가 된다.
     *   - AI 판단 대기: {@link VulnerabilityService#getUnassessedVulnerabilities()} (/api/ai/vulnerabilities/pending)
     *   - fix-plan 대기: {@link FixPlanService#getPendingFixPlanTargets()} (/api/ai/fix-plans/pending)
     *   - 설명 요약 대기: {@link CveSummaryService#getPendingSummaryTargets()} (/api/ai/summaries/pending)
     *   - 영향 분석 대기: {@link UpgradeImpactService#getPendingTargets()} (/api/ai/impacts/pending)
     *
     * <p>배치는 Claude API를 호출한다(과금). 이미 떠 있으면 {@code triggerAsync}가 건너뛰므로 스캔을
     * 연달아 돌려도 프로세스가 쌓이지 않는다. 여기서 실패해도 스캔 결과는 이미 저장됐으니 스캔은
     * 성공으로 끝내고 로그만 남긴다.
     */
    private void triggerAiAssessmentIfNeeded() {
        if (!aiAssessmentTriggerService.isAutoTriggerEnabled()) {
            // 대기열 조회(요약 대기는 설명 전체를 읽는다)도 할 필요가 없어 바로 끝낸다. 대기열은 그대로 남는다.
            log.info("공통코드 {}/{}가 꺼져 있어 스캔 후 AI 배치를 띄우지 않습니다.",
                    AiAssessmentTriggerService.CONFIG_GROUP, AiAssessmentTriggerService.AUTO_TRIGGER_CODE);
            return;
        }
        try {
            boolean hasPendingAssessment = !vulnerabilityService.getUnassessedVulnerabilities().isEmpty();
            boolean hasPendingFixPlan = !fixPlanService.getPendingFixPlanTargets().isEmpty();
            boolean hasPendingSummary = !cveSummaryService.getPendingSummaryTargets().isEmpty();
            // 영향 분석은 보통 같은 배치 안에서 fix-plan 직후에 돈다. 여기서는 지난번에 일시 오류(FETCH_FAILED)로
            // 끝난 건을 다시 시도할 수 있게 대기열로 본다.
            boolean hasPendingImpact = !upgradeImpactService.getPendingTargets().isEmpty();
            if (hasPendingAssessment || hasPendingFixPlan || hasPendingSummary || hasPendingImpact) {
                aiAssessmentTriggerService.triggerAsync();
            } else {
                log.info("AI 판단·fix-plan·설명 요약·영향 분석 대기 건이 없어 AI 배치를 띄우지 않습니다.");
            }
        } catch (Exception e) {
            log.warn("AI 배치 실행 판단/시작에 실패했습니다(스캔 결과는 저장됨): {}", e.toString());
        }
    }

    /**
     * import·설정 키 목록을 JSON으로. 영향 분석의 "우리 코드" 대조용 부가 정보라, 실패해도 스캔은 계속하고 null을 남긴다 —
     * 화면은 null을 "판단 불가"로 보여준다(없는 걸 "안 보임"으로 보이면 영향 없음처럼 읽힌다).
     */
    private String extractSourceUsage(File projectDir, String systemName) {
        try {
            SourceUsage usage = sourceUsageExtractor.extract(projectDir.toPath());
            log.info("[{}] 소스 사용 목록 추출: java 파일 {}개, import {}종, 설정 키 {}개",
                    systemName, usage.javaFileCount(), usage.imports().size(), usage.configKeys().size());
            return objectMapper.writeValueAsString(usage);
        } catch (Exception e) {
            log.warn("[{}] 소스 사용 목록 추출 실패(스캔은 계속 진행): {}", systemName, e.toString());
            return null;
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