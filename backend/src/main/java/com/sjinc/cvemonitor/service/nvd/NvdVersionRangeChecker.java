package com.sjinc.cvemonitor.service.nvd;

import com.sjinc.cvemonitor.dto.nvd.NvdConfiguration;
import com.sjinc.cvemonitor.dto.nvd.NvdCpeMatch;
import com.sjinc.cvemonitor.dto.nvd.NvdNode;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * NVD가 구조화된 형태로 내려주는 영향 버전 범위(cpeMatch)와 설치 버전을 직접 비교해서
 * 취약 여부를 계산한다. AI가 description 프로즈를 읽고 범위를 추측하게 하면, 설명 뒷부분에
 * 나오는 "Affected versions" 목록을 놓치거나(특히 설명이 축약될 때) 여러 브랜치가 나열된
 * 경우 일부를 빠뜨리는 실수가 실제로 있었다 — 이 계산은 그 자리를 대체하는 결정론적 판정이다.
 *
 * <p>AND 조합(다른 제품과 함께 쓰일 때만 취약한 조건부 케이스)은 다루지 않는다 — 이 시스템이
 * 다루는 CVE는 거의 다 "이 컴포넌트의 이 버전 범위면 취약"이라는 단일 조건이라, 모든
 * cpeMatch를 하나의 OR 조합으로 취급한다.
 */
@Component
public class NvdVersionRangeChecker {

    /** 범위 판정 결과. matched가 null이면 "구조화된 범위 데이터가 아예 없어서 판단 불가"라는 뜻이다. */
    public record MatchResult(Boolean matched, String matchedRange) {
        public static final MatchResult UNKNOWN = new MatchResult(null, null);
    }

    public MatchResult check(List<NvdConfiguration> configurations, String installedVersion) {
        if (configurations == null || configurations.isEmpty() || installedVersion == null || installedVersion.isBlank()) {
            return MatchResult.UNKNOWN;
        }

        ComparableVersion installed;
        try {
            installed = new ComparableVersion(installedVersion);
        } catch (Exception e) {
            return MatchResult.UNKNOWN;
        }

        boolean anyRangeSeen = false;
        for (NvdConfiguration configuration : configurations) {
            if (configuration.getNodes() == null) continue;
            for (NvdNode node : configuration.getNodes()) {
                if (node.getCpeMatch() == null) continue;
                for (NvdCpeMatch cpeMatch : node.getCpeMatch()) {
                    if (!cpeMatch.isVulnerable()) continue;
                    anyRangeSeen = true;
                    if (isWithinRange(installed, cpeMatch)) {
                        return new MatchResult(true, describeRange(cpeMatch));
                    }
                }
            }
        }

        // vulnerable=true인 cpeMatch가 하나도 없었으면(전부 vulnerable=false거나 구조 자체가 비어있으면)
        // 이 데이터로는 뭘 말하는지 알 수 없으니 판단을 포기한다 — false로 단정하지 않는다.
        return anyRangeSeen ? new MatchResult(false, null) : MatchResult.UNKNOWN;
    }

    private boolean isWithinRange(ComparableVersion installed, NvdCpeMatch cpeMatch) {
        if (isSet(cpeMatch.getVersionStartIncluding())
                && installed.compareTo(new ComparableVersion(cpeMatch.getVersionStartIncluding())) < 0) {
            return false;
        }
        if (isSet(cpeMatch.getVersionStartExcluding())
                && installed.compareTo(new ComparableVersion(cpeMatch.getVersionStartExcluding())) <= 0) {
            return false;
        }
        if (isSet(cpeMatch.getVersionEndIncluding())
                && installed.compareTo(new ComparableVersion(cpeMatch.getVersionEndIncluding())) > 0) {
            return false;
        }
        if (isSet(cpeMatch.getVersionEndExcluding())
                && installed.compareTo(new ComparableVersion(cpeMatch.getVersionEndExcluding())) >= 0) {
            return false;
        }
        return true;
    }

    private boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private String describeRange(NvdCpeMatch cpeMatch) {
        StringBuilder sb = new StringBuilder();
        if (isSet(cpeMatch.getVersionStartIncluding())) sb.append(">= ").append(cpeMatch.getVersionStartIncluding());
        if (isSet(cpeMatch.getVersionStartExcluding())) sb.append("> ").append(cpeMatch.getVersionStartExcluding());
        if (!sb.isEmpty()) sb.append(", ");
        if (isSet(cpeMatch.getVersionEndIncluding())) sb.append("<= ").append(cpeMatch.getVersionEndIncluding());
        if (isSet(cpeMatch.getVersionEndExcluding())) sb.append("< ").append(cpeMatch.getVersionEndExcluding());
        return sb.isEmpty() ? "(버전 제한 없음)" : sb.toString();
    }
}
