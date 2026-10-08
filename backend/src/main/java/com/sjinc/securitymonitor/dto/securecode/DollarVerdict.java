package com.sjinc.securitymonitor.dto.securecode;

import java.util.List;

/**
 * MyBatis {@code ${}} 한 곳의 값 출처 판정(MybatisDollarTracer).
 *
 * @param path      저장소 루트 기준 매퍼 XML 경로(구분자 /)
 * @param line      {@code ${}}가 있는 줄
 * @param statement 판정에 쓴 구문 id(조각이면 그 조각을 include한 구문들 중 가장 나쁜 것)
 * @param expr      {@code ${}} 안의 식
 * @param key       값을 꺼내는 파라미터 키
 * @param safety    판정
 * @param evidence  판정 근거 — 값이 지나온 길을 위에서부터(호출 쪽 → 매퍼 쪽) 한 줄씩
 * @param display   파일에 적힌 모양 그대로(${ym}, #{compCd}, iBatis $sortCol$·#compCd#) — 메시지 표시용
 */
public record DollarVerdict(String path, int line, String statement, String expr, String key,
                            TraceSafety safety, List<String> evidence, String display) {
}
