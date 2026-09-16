package com.sjinc.cvemonitor.service.osv;

import com.sjinc.cvemonitor.dto.osv.OsvAffected;
import com.sjinc.cvemonitor.dto.osv.OsvEvent;
import com.sjinc.cvemonitor.dto.osv.OsvRange;
import com.sjinc.cvemonitor.dto.osv.OsvVulnDetail;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * OSV의 구조화된 영향 버전 범위(affected[].ranges[].events[] - introduced/fixed/last_affected)로
 * 설치 버전이 실제 영향 범위 안에 있는지 판단한다.
 *
 * <p>NVD의 configurations가 없을 때(흔하다) description 프로즈를 다시 해석하는 대신 이걸 먼저
 * 쓴다. 실제로 겪은 문제: micrometer-core 1.12.6 / CVE-2026-40984에서 NVD 설명 프로즈만 보고
 * "1.10~1.12는 영향 범위 공백"이라고 잘못 판단했는데, OSV의 구조화 데이터엔 "introduced: 1.10.0,
 * last_affected: 1.13.15"라는 범위가 명시돼 있었다 — 이 CVE를 애초에 스캔이 잡아낸 근거이기도
 * 하다. 이미 스캔 때 받아온 OSV 상세 데이터를 그대로 쓰면 이런 프로즈 오독을 원천 차단한다.
 */
@Component
public class OsvVersionRangeChecker {

    public record MatchResult(Boolean matched, String matchedRange) {
        public static final MatchResult UNKNOWN = new MatchResult(null, null);
    }

    public MatchResult check(List<OsvVulnDetail> vulnDetails, String groupId, String artifactId, String installedVersion) {
        if (vulnDetails == null || vulnDetails.isEmpty() || installedVersion == null || installedVersion.isBlank()) {
            return MatchResult.UNKNOWN;
        }

        ComparableVersion installed;
        try {
            installed = new ComparableVersion(installedVersion);
        } catch (Exception e) {
            return MatchResult.UNKNOWN;
        }

        String packageName = groupId + ":" + artifactId;
        boolean anyRangeSeen = false;

        for (OsvVulnDetail detail : vulnDetails) {
            if (detail == null || detail.getAffected() == null) continue;
            for (OsvAffected affected : detail.getAffected()) {
                if (affected.getPackageInfo() == null
                        || !"Maven".equals(affected.getPackageInfo().getEcosystem())
                        || !packageName.equals(affected.getPackageInfo().getName())) {
                    continue;
                }
                if (affected.getRanges() == null) continue;
                for (OsvRange range : affected.getRanges()) {
                    if (range.getEvents() == null || range.getEvents().isEmpty()) continue;
                    anyRangeSeen = true;
                    String matchedDescription = checkRange(range, installed);
                    if (matchedDescription != null) {
                        return new MatchResult(true, matchedDescription);
                    }
                }
            }
        }

        // 이 패키지에 해당하는 range를 하나라도 봤는데 어디에도 안 걸렸으면 확실히 범위 밖이다.
        // 애초에 range 자체를 못 찾았으면(패키지 불일치 등) 판단 불가로 둔다.
        return anyRangeSeen ? new MatchResult(false, null) : MatchResult.UNKNOWN;
    }

    /**
     * 하나의 range(introduced/fixed/last_affected가 순서대로 나열된 events)를 훑으면서 installed가
     * 걸리는 구간이 있으면 그 구간 설명을 돌려주고, 없으면 null. OSV 스펙상 한 range 안에 introduced
     * -fixed 쌍이 여러 번 나올 수 있어(브랜치 재도입 등) 상태 기계처럼 순서대로 처리한다.
     */
    private String checkRange(OsvRange range, ComparableVersion installed) {
        String openStart = null; // 현재 열려있는 구간의 시작(introduced) 값. null이면 열린 구간 없음.

        for (OsvEvent event : range.getEvents()) {
            if (event.getIntroduced() != null) {
                openStart = event.getIntroduced();
                continue;
            }
            if (openStart == null) continue; // 시작 없이 끝만 나오는 이상 데이터는 무시한다.

            if (event.getFixed() != null) {
                if (isAtLeast(installed, openStart) && isBelow(installed, event.getFixed())) {
                    return ">= " + openStart + ", < " + event.getFixed();
                }
                openStart = null;
            } else if (event.getLastAffected() != null) {
                if (isAtLeast(installed, openStart) && isAtMost(installed, event.getLastAffected())) {
                    return ">= " + openStart + ", <= " + event.getLastAffected();
                }
                openStart = null;
            }
            // limit은 "이 이상은 알 수 없음" 표시라 상한 판단에 안 쓴다.
        }

        // 구간이 끝(fixed/last_affected) 없이 열린 채로 끝나면 그 이후 전부 영향받는다는 뜻이다.
        if (openStart != null && isAtLeast(installed, openStart)) {
            return ">= " + openStart + " (수정 버전 미공개)";
        }
        return null;
    }

    private boolean isAtLeast(ComparableVersion installed, String start) {
        if ("0".equals(start)) return true; // OSV 관례: "0"은 처음부터라는 뜻.
        try {
            return installed.compareTo(new ComparableVersion(start)) >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isBelow(ComparableVersion installed, String end) {
        try {
            return installed.compareTo(new ComparableVersion(end)) < 0;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isAtMost(ComparableVersion installed, String end) {
        try {
            return installed.compareTo(new ComparableVersion(end)) <= 0;
        } catch (Exception e) {
            return false;
        }
    }
}
