package com.sjinc.securitymonitor.dto.ai;

/** 배치가 대표 건의 판별·실패를 함께 적용해 달라고 돌려주는 같은 출처 지점(pending에서 받은 id·inputHash 그대로). */
public record SameOriginRef(Long id, String inputHash) {
}
