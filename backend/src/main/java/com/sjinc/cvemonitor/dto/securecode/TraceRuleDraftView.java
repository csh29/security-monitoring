package com.sjinc.cvemonitor.dto.securecode;

import java.util.List;

/**
 * 추적 규칙 초안 화면 응답(TraceRuleDraftService). 서버는 초안을 보여주기만 하고 trace-rules.yml은 사람이 고친다.
 *
 * @param yaml          trace-rules.yml에 붙여 넣을 초안(근거 주석 포함)
 * @param items         초안 항목별 지금 설정 대비 상태
 * @param changes       초안을 반영하면 판정이 바뀌는 ${}
 * @param changeSummary "클라이언트 값 → 세션 값으로 덮어씀 11" 같은 바뀜 집계
 * @param notes         자동으로 찾지 못하는 방식의 흔적 등 사람이 직접 볼 것
 * @param failedFiles   구문 분석하지 못한 Java 파일 수 — 0이 아니면 초안이 빠진 것이 있을 수 있다
 */
public record TraceRuleDraftView(
        String systemName,
        String yaml,
        List<Item> items,
        List<Change> changes,
        List<String> changeSummary,
        List<String> notes,
        int failedFiles
) {
    public record Item(String kind, String value, String status, String statusLabel, String detail, List<String> evidence) {
    }

    public record Change(String location, String expr, String before, String after) {
    }
}
