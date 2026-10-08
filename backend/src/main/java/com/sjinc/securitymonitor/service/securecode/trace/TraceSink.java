package com.sjinc.securitymonitor.service.securecode.trace;

import java.util.Map;

/**
 * 실행 지점 규칙이 연계 추적에 맡기는 값 — 규칙 파일의 {@code metadata.trace}(·{@code trace_fixed_host})로 선언한다(RuleSetLoader가 읽는다).
 * 규칙마다 따라갈 인자를 자바에 적어 두면 규칙을 늘릴 때마다 자바를 고쳐야 했다. 이제 SinkTracer는 규칙을 모른 채 탐지 범위의 식에서
 * 선언대로 값을 꺼내 출처를 따라간다.
 *
 * @param target    따라갈 값
 * @param fixedHost 값이 고정 호스트로 시작하는 주소("https://host/…")면 그 뒤가 요청값이어도 서버 값으로 본다(SSRF)
 */
public record TraceSink(Target target, boolean fixedHost) {

    public enum Target {
        /** 걸린 호출·생성의 인자 전부(명령 실행 exec(cmd, env), 파일 new File(dir, name)) — 가장 위험한 것으로 판정 */
        ARGUMENTS("arguments"),
        /** 걸린 호출·생성의 첫 인자(SQL 실행의 쿼리, 주소 객체·HTTP 호출의 주소) — 나머지 인자는 바인딩 값·응답 타입이다 */
        FIRST_ARGUMENT("first-argument"),
        /** 걸린 식 자체 — 규칙이 focus-metavariable로 값만 가리킬 때(업로드 저장의 저장 위치처럼 인자 자리가 호출마다 다를 때) */
        VALUE("value");

        private final String yamlName;

        Target(String yamlName) {
            this.yamlName = yamlName;
        }
    }

    /**
     * 규칙 하나의 metadata에서 읽는다. trace가 없으면 null(연계 추적 대상이 아님). 값이 틀리면 점검을 멈춘다 —
     * 조용히 넘기면 그 규칙의 탐지가 판정 없이 저장돼 "추적이 안전하다고 본 것"과 구분이 안 된다.
     */
    public static TraceSink fromMetadata(String ruleId, Object metadata) {
        if (!(metadata instanceof Map<?, ?> map) || map.get("trace") == null) return null;
        String value = String.valueOf(map.get("trace"));
        for (Target target : Target.values()) {
            if (target.yamlName.equals(value)) {
                return new TraceSink(target, Boolean.TRUE.equals(map.get("trace_fixed_host")));
            }
        }
        throw new IllegalArgumentException("규칙 " + ruleId + "의 metadata.trace 값이 틀렸습니다: " + value
                + " (arguments·first-argument·value 중 하나)");
    }
}
