package com.sjinc.securitymonitor.dto.ai;

import com.sjinc.securitymonitor.domain.VersionJump;

/** 영향 분석 배치(stage 4)가 가져갈 업그레이드 한 건. 여러 앱의 fix-plan에 같은 건이 있어도 하나로 내려간다. */
public record UpgradeImpactTarget(String coordinate, String fromVersion, String toVersion, VersionJump jump) {
}
