package com.sjinc.cvemonitor.dto.securecode;

/** 홈 대시보드 집계용 — (처리여부, 심각도)별 탐지 건수. JPQL 생성자 표현식으로 받는다. */
public record SecureCodeStatusCount(String status, String severity, long count) {
}
