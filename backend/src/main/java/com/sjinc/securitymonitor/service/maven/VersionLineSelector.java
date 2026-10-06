package com.sjinc.securitymonitor.service.maven;

import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.Collection;

/**
 * "설치 버전과 같은 메이저 라인 후보 중, 설치 버전보다 높은 값의 최솟값을 고른다"는 규칙 — 원래
 * assess.system.md에서 AI에게 시키던 규칙인데, 순수 버전 비교라 결정론적으로 계산 가능하다.
 * {@link com.sjinc.securitymonitor.service.osv.OsvFixVersionResolver}(재귀 검증)와 자동 판정
 * (VulnerabilityService)이 공통으로 쓴다.
 */
public final class VersionLineSelector {

    private VersionLineSelector() {
    }

    /** 후보가 여러 개면 다운그레이드/제자리를 제외하고, 설치 버전과 같은 메이저 라인 중 최솟값을 고른다. 없으면 null. */
    public static String pickLowestSameLineAbove(Collection<String> candidates, String currentVersion) {
        ComparableVersion current;
        try {
            current = new ComparableVersion(currentVersion);
        } catch (Exception e) {
            return null;
        }
        int currentMajor = majorVersion(currentVersion);

        String best = null;
        ComparableVersion bestComparable = null;
        for (String candidate : candidates) {
            if (majorVersion(candidate) != currentMajor) continue;
            ComparableVersion candidateComparable;
            try {
                candidateComparable = new ComparableVersion(candidate);
            } catch (Exception e) {
                continue;
            }
            if (candidateComparable.compareTo(current) <= 0) continue; // 다운그레이드/제자리는 후보에서 제외
            if (bestComparable == null || candidateComparable.compareTo(bestComparable) < 0) {
                best = candidate;
                bestComparable = candidateComparable;
            }
        }
        return best;
    }

    public static int majorVersion(String version) {
        String token = version.split("[.\\-]")[0];
        String digits = token.replaceAll("[^0-9]", "");
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
