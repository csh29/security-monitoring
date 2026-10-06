package com.sjinc.cvemonitor.dto.securecode;

/** 코드 점검 화면의 "점검" 버튼. 앱 관리에 등록된 앱만 점검한다(appId로만 받는다 — 임의 URL을 받지 않는다). */
public record SecureCodeScanRequest(Long appId) {
}
