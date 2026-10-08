package com.sjinc.securitymonitor.dto.securecode;

/**
 * 연계 추적 근거 한 걸음이 가리키는 줄의 주변 코드(SecureCodeSnippetBuilder.traceCode). 점검 때 만들어 둔다 — clone은 점검이 끝나면 지운다.
 *
 * @param path      저장소 기준 경로
 * @param line      근거가 가리키는 줄(화면에서 강조)
 * @param startLine code 첫 줄의 줄 번호
 * @param code      그 줄 앞뒤 몇 줄
 */
public record TraceStepCode(String path, int line, int startLine, String code) {
}
