package com.sjinc.securitymonitor.dto.securecode;

/** 재점검 비교(SecureCodeReconciler) 결과 건수. */
public record SecureCodeApplyResult(int newCount, int resolvedCount) {
}
