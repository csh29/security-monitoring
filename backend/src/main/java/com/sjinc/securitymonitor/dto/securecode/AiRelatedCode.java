package com.sjinc.securitymonitor.dto.securecode;

/**
 * AI 판별에 탐지 메서드와 함께 보내는 다른 메서드 하나(SecureCodeSnippetBuilder.aiRelatedCode). 메서드 하나만 보면 값이 다른 파일에서
 * 정해지는 경우(이름은 요청값 같지만 상수를 돌려주는 헬퍼 등)를 AI가 추측으로 채워 틀렸다.
 *
 * @param path      저장소 기준 경로(.java만 — 설정 파일은 보내지 않는다)
 * @param startLine code 첫 줄의 줄 번호
 * @param code      메서드 코드(길면 앞부분만)
 * @param reason    왜 같이 보내는가(연계 추적 경로 / 탐지 메서드가 부르는 메서드)
 */
public record AiRelatedCode(String path, int startLine, String code, String reason) {
}
