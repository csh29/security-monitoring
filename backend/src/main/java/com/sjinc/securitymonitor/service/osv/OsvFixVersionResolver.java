package com.sjinc.securitymonitor.service.osv;

import com.sjinc.securitymonitor.dto.osv.OsvAffected;
import com.sjinc.securitymonitor.dto.osv.OsvEvent;
import com.sjinc.securitymonitor.dto.osv.OsvRange;
import com.sjinc.securitymonitor.dto.osv.OsvVulnDetail;
import com.sjinc.securitymonitor.service.maven.VersionLineSelector;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 제안된 수정 버전 자체에 OSV에 알려진 다른 취약점이 없는지 재귀적으로 검증한다 — 설치 버전 기준 스캔은 수정 버전에만 걸린 CVE를 못 본다.
 * AI 없이 결정론적으로 같은 메이저 라인 안의 최소 상향만 따라가고, 메이저 업그레이드가 필요하면 멈춰 사람 확인 상태를 돌려준다.
 */
@Service
public class OsvFixVersionResolver {

    /** 무한 루프/이상 데이터 방어용 상한. 이 깊이를 넘어서도 안 끝나면 사람이 확인해야 한다. */
    private static final int MAX_DEPTH = 5;

    private final OsvClient osvClient;

    public OsvFixVersionResolver(OsvClient osvClient) {
        this.osvClient = osvClient;
    }

    public enum Status {
        /** OSV에 이 버전에 대한 알려진 취약점이 없다. */
        CLEAN,
        /** MAX_DEPTH까지 재확인했는데도 계속 새 취약점이 나온다. 사람 확인 필요. */
        MAX_DEPTH_REACHED,
        /** 같은 메이저 라인 안에 더 이상 수정 버전이 없다(메이저 업그레이드 필요). 자동 진행 안 함. */
        NO_SAME_LINE_FIX,
    }

    public record Resolution(String finalVersion, List<String> chain, Status status) {
    }

    public Resolution resolve(String groupId, String artifactId, String candidateVersion) {
        List<String> chain = new ArrayList<>();
        String current = candidateVersion;

        for (int depth = 0; depth < MAX_DEPTH; depth++) {
            chain.add(current);
            List<OsvVulnDetail> vulns = osvClient.queryVersion(groupId, artifactId, current);
            if (vulns.isEmpty()) {
                return new Resolution(current, List.copyOf(chain), Status.CLEAN);
            }

            String next = nextVersion(vulns, groupId, artifactId, current);
            if (next == null) {
                return new Resolution(current, List.copyOf(chain), Status.NO_SAME_LINE_FIX);
            }
            current = next;
        }
        return new Resolution(current, List.copyOf(chain), Status.MAX_DEPTH_REACHED);
    }

    /**
     * 이 버전에 걸린 취약점들의 수정 버전 중 같은 메이저 라인에서 현재보다 높은 최솟값을 고른다.
     * 한 공지가 여러 패키지를 다룰 때 엉뚱한 패키지의 버전을 섞지 않게 groupId:artifactId가 정확히 일치하는 항목만 본다.
     */
    private String nextVersion(List<OsvVulnDetail> vulns, String groupId, String artifactId, String currentVersion) {
        String packageName = groupId + ":" + artifactId;
        Set<String> candidates = new LinkedHashSet<>();
        for (OsvVulnDetail vuln : vulns) {
            if (vuln.getAffected() == null) continue;
            for (OsvAffected affected : vuln.getAffected()) {
                if (affected.getPackageInfo() == null
                        || !"Maven".equals(affected.getPackageInfo().getEcosystem())
                        || !packageName.equals(affected.getPackageInfo().getName())) {
                    continue;
                }
                if (affected.getRanges() == null) continue;
                for (OsvRange range : affected.getRanges()) {
                    if (range.getEvents() == null) continue;
                    for (OsvEvent event : range.getEvents()) {
                        if (event.getFixed() != null) candidates.add(event.getFixed());
                    }
                }
            }
        }
        if (candidates.isEmpty()) return null;
        return VersionLineSelector.pickLowestSameLineAbove(candidates, currentVersion);
    }
}
