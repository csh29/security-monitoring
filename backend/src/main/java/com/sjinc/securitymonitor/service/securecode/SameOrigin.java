package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;

/**
 * 한 요청값이 여러 위험 지점에 들어간 탐지를 묶는다. 탐지는 그대로 두고 화면만 묶으며, AI는 같은 원인을 두 번 묻지 않게 묶음당 한 번 판별한다.
 * 열쇠는 앱·CWE(약점이 다르면 판별을 나눠야 한다)·연계 추적의 첫 걸음이며, 추적 근거가 없는 탐지는 묶지 않는다.
 */
public final class SameOrigin {

    private SameOrigin() {
    }

    /** 묶음 열쇠. 근거가 없으면 null(혼자다). */
    public static String key(Long appId, String cwe, String traceEvidence) {
        if (traceEvidence == null || traceEvidence.isBlank()) return null;
        String first = traceEvidence.strip().split("\n", 2)[0].strip();
        return first.isEmpty() ? null : appId + "|" + (cwe == null ? "" : cwe.strip()) + "|" + first;
    }

    public static String key(SecureCodeFinding f) {
        return key(f.getAppId(), f.getCwe(), f.getTraceEvidence());
    }
}
