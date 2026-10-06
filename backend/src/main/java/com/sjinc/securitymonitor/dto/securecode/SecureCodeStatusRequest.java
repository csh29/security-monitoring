package com.sjinc.securitymonitor.dto.securecode;

/**
 * 코드 점검 결과 화면 "저장" — 처리여부나 비고를 바꾼 행 하나. status는 공통코드 SC_STATUS 값.
 * 서버는 실제로 달라진 항목만 반영한다(SecureCodeFindingService.changeStatuses).
 */
public record SecureCodeStatusRequest(Long id, String status, String remark) {
}
