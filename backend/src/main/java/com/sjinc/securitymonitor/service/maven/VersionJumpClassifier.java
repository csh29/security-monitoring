package com.sjinc.securitymonitor.service.maven;

import com.sjinc.securitymonitor.domain.VersionJump;
import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.ArrayList;
import java.util.List;

/**
 * fix-plan이 제안한 버전 변경(from → to)이 패치/마이너/메이저 중 어느 폭의 점프인지 결정론적으로 분류한다.
 *
 * <p>업그레이드 영향 분석에서 AI를 부를지 말지를 이 결과로 먼저 거른다 — 패치 점프는 하위 호환이 원칙이라
 * AI 분석 없이 "회귀 테스트만"으로 끝내고, 마이너·메이저만 릴리스 노트를 읽혀 분석한다. 점프 폭은 순수 버전
 * 비교라 AI에게 맡길 이유가 없다(VersionLineSelector와 같은 이유).
 */
public final class VersionJumpClassifier {

    private VersionJumpClassifier() {
    }

    public static VersionJump classify(String fromVersion, String toVersion) {
        List<Integer> from = numericParts(fromVersion);
        List<Integer> to = numericParts(toVersion);
        if (from.isEmpty() || to.isEmpty()) {
            return VersionJump.UNKNOWN;
        }
        // 숫자 조각만으로는 5.3.18과 5.3.18.RELEASE, 1.0-RC1과 1.0을 구분하지 못한다. 순서 판단은 Maven 규칙
        // (ComparableVersion)으로 하고, 숫자 조각은 "어느 자리가 바뀌었나"를 보는 데만 쓴다.
        if (new ComparableVersion(toVersion).compareTo(new ComparableVersion(fromVersion)) <= 0) {
            return VersionJump.UNKNOWN;
        }
        if (!part(from, 0).equals(part(to, 0))) {
            return VersionJump.MAJOR;
        }
        if (!part(from, 1).equals(part(to, 1))) {
            return VersionJump.MINOR;
        }
        return VersionJump.PATCH;
    }

    /**
     * 앞에서부터 이어지는 숫자 조각만 뽑는다. "5.2.20.RELEASE" → [5, 2, 20], "2023.0.3" → [2023, 0, 3],
     * "1.0-RC1" → [1, 0]. 첫 조각부터 숫자가 아니면 빈 목록(해석 불가).
     */
    private static List<Integer> numericParts(String version) {
        List<Integer> parts = new ArrayList<>();
        if (version == null) {
            return parts;
        }
        for (String token : version.trim().split("[.\\-]")) {
            if (!token.matches("\\d{1,9}")) {
                break;
            }
            parts.add(Integer.parseInt(token));
        }
        return parts;
    }

    /** "1.10"처럼 자리가 모자라면 0으로 본다(1.10 → 1.10.1은 패치). */
    private static Integer part(List<Integer> parts, int index) {
        return index < parts.size() ? parts.get(index) : 0;
    }
}
