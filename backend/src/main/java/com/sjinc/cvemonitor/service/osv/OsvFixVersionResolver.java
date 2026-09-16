package com.sjinc.cvemonitor.service.osv;

import com.sjinc.cvemonitor.dto.osv.OsvAffected;
import com.sjinc.cvemonitor.dto.osv.OsvEvent;
import com.sjinc.cvemonitor.dto.osv.OsvRange;
import com.sjinc.cvemonitor.dto.osv.OsvVulnDetail;
import com.sjinc.cvemonitor.service.maven.VersionLineSelector;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * "수정 버전"이라고 제안된 값 자체가 실제로 깨끗한지(OSV에 알려진 다른 취약점이 없는지) 재귀적으로
 * 검증한다. 실제로 겪은 문제: pgjdbc 42.7.2가 CVE-2026-42198에 걸려 42.7.11로 올리라고 했는데,
 * 42.7.11 자체가 별개의 CVE-2026-54291(42.7.4~42.7.11 영향, 42.7.12에서 수정)에 걸려 있었다.
 * 설치 버전 기준 OSV 스캔은 이 CVE를 애초에 못 본다 — 설치 버전(42.7.2)은 그 영향 범위 밖이라서다.
 * "추천한 버전 자체"를 다시 OSV에 물어봐야만 이런 연쇄를 잡을 수 있다.
 *
 * <p>AI 판단에 맡기지 않고 자바에서 결정론적으로 처리한다 — 같은 메이저 라인 안에서 최소 상향만
 * 자동으로 따라가고, 메이저 업그레이드가 필요해지면(같은 라인에 더 이상 수정 버전이 없으면) 자동
 * 진행을 멈추고 사람 확인이 필요하다는 상태를 돌려준다.
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
        public boolean isClean() {
            return status == Status.CLEAN;
        }
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
     * 이 버전에 걸린 취약점들의 수정 버전 후보 중, 같은 메이저 라인이면서 현재보다 높은 값 중
     * 최솟값을 고른다. 후보 추출 시 groupId:artifactId가 정확히 일치하는 affected 항목만 본다 —
     * 한 취약점 공지가 여러 패키지를 함께 다룰 때(예: 관련 라이브러리 묶음) 엉뚱한 패키지의 수정
     * 버전 번호를 섞어 쓰는 걸 막기 위함이다.
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
