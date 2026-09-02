package com.sjinc.cvemonitor.service.scan;

import com.sjinc.cvemonitor.domain.MavenDependency;
import com.sjinc.cvemonitor.dto.cve.OsvBatchResultItem;
import com.sjinc.cvemonitor.dto.cve.OsvVulnRef;
import com.sjinc.cvemonitor.dto.git.ScanResult;
import com.sjinc.cvemonitor.dto.git.ScanResult.DependencyFinding;
import com.sjinc.cvemonitor.dto.osv.OsvVulnDetail;
import com.sjinc.cvemonitor.service.osv.OsvClient;
import com.sjinc.cvemonitor.service.git.GitCloneService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ScanOrchestrationService {

    private final GitCloneService gitCloneService;
    private final com.sjinc.cvemonitor.service.maven.MavenDependencyExtractor dependencyExtractor;
    private final OsvClient osvClient;

    @Value("${git.access.token}")
    private String gitAccessToken;

    public ScanResult scanRepository(String repoUrl, String branch) throws Exception {
        File projectDir = gitCloneService.cloneRepository(repoUrl, branch, gitAccessToken);
        try {
            List<MavenDependency> dependencies = dependencyExtractor.extract(projectDir);
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
                        identifier, detail.getSummary())));
            }

            // TODO: findings를 VulnerabilityFinding 엔티티로 저장 (상태=미확인) + 담당자 알림 트리거
            return new ScanResult(repoUrl, branch, dependencies.size(), findings);
        } finally {
            gitCloneService.cleanup(projectDir);
        }
    }

    private String extractCveOrId(OsvVulnDetail detail) {
        if (detail.getAliases() == null) return detail.getId();
        return detail.getAliases().stream()
                .filter(a -> a.startsWith("CVE-"))
                .findFirst()
                .orElse(detail.getId());
    }
}