package com.sjinc.securitymonitor.exception;

/**
 * 코드 점검 실패 중 화면에 그대로 보여줘도 되는 것(설치 안 됨, 시간 초과 등). 메시지에 서버 경로를 넣지 않는다 —
 * 다른 예외는 내부 경로가 섞일 수 있어 화면에 종류만 보인다(SecureCodeScanService.toErrorMessage).
 */
public class SecureCodeScanException extends RuntimeException {

    /** 다른 점검이 돌고 있어 시작하지 않았다(409). 나머지는 점검 실패(500). */
    private final boolean busy;

    public SecureCodeScanException(String message, Throwable cause) {
        this(message, cause, false);
    }

    private SecureCodeScanException(String message, Throwable cause, boolean busy) {
        super(message, cause);
        this.busy = busy;
    }

    public static SecureCodeScanException busy() {
        return new SecureCodeScanException("다른 코드 점검이 진행 중입니다. 끝난 뒤 다시 실행해주세요.", null, true);
    }

    public boolean isBusy() {
        return busy;
    }
}
