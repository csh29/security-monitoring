package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.domain.SecureCodeFinding;

/**
 * 같은 출처 묶음 — 한 요청값이 여러 위험 지점에 들어가면(CKEditor pgmID → 폴더 만들기 FrameFileUtil:46, 파일 쓰기 :88) 지점마다 탐지가 따로 생긴다.
 * 지점은 각각 실제 위험이라 탐지는 그대로 두고, 화면은 묶어서 보여주고 AI는 묶음당 한 번만 판별한다(같은 원인을 두 번 묻지 않게 — 비용·시간).
 *
 * <p>열쇠는 같은 앱·같은 CWE·연계 추적의 첫 걸음(값이 처음 들어온 곳, 예: "CkEditorController.java:51 요청 값 request.getParameter("pgmID")").
 * CWE를 넣는 것은 같은 값이 SQL과 파일 경로에 함께 들어가면 약점이 달라 판별을 나눠야 해서다. 근거가 없는 탐지(추적 대상이 아닌 규칙)는 묶지 않는다.
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
