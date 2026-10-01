package com.sjinc.cvemonitor.dto.ai;

import java.util.List;

/**
 * 영향 분석의 breaking change가 이 앱 코드에 해당하는지 import·설정 키로 대조한 결과(CodeUsageMatcher).
 *
 * <p>status: USED(정확한 클래스·영향받는 패키지·설정 키가 일치) / POSSIBLE(짧은 이름·와일드카드 import로만 걸림) / NOT_FOUND(import·설정 키에서
 * 안 보임 — 영향이 없다는 뜻은 아니다) / UNKNOWN(대조할 이름이 없거나 소스 목록이 없음).
 *
 * @param items  impact.breakingChanges와 같은 순서·같은 개수
 * @param reason 전체가 UNKNOWN인 이유(소스 목록 없음 등). 없으면 null
 */
public record CodeUsageView(String status, List<Item> items, String reason) {

    public record Item(String status, List<String> matches) {
    }
}
