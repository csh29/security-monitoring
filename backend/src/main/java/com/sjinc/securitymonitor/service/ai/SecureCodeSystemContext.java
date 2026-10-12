package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;

import java.util.ArrayList;
import java.util.List;

/**
 * AI 판별에 붙이는 시스템 구조 사실(trace-rules.yml의 프레임워크 구조·세션 덮어쓰기·로그인 정보 이름 등). 설정형 탐지(CSRF·전체 허용)의
 * 판단 근거가 호출로 이어지지 않은 곳에 있어 함께 보낸다. 코드가 아닌 이름과 근거 한 줄이며 보내기 전에 비밀값을 가린다.
 */
public final class SecureCodeSystemContext {

    /** 줄 수·한 줄 길이 상한 — 구조 기록이 길어져도 판별 입력이 커지지 않게. */
    static final int MAX_LINES = 40;
    static final int MAX_LINE_LENGTH = 300;

    private SecureCodeSystemContext() {
    }

    /** system의 구조 사실들. 아는 게 없으면 빈 목록. */
    public static List<String> lines(TraceRules rules, String system) {
        List<String> lines = new ArrayList<>();
        if (rules == null || system == null) return lines;
        TraceRules effective = rules.forSystem(system);
        for (TraceRules.FrameworkFact fact : rules.frameworks().getOrDefault(system, List.of())) {
            lines.add(fact.kind() + ": " + fact.value() + (fact.evidence() == null || fact.evidence().isBlank() ? "" : " — " + fact.evidence()));
        }
        for (TraceRules.SessionOverwrite o : rules.sessionOverwrites()) {
            lines.add("세션 덮어쓰기 장치(추적 규칙): " + o.name() + " — @" + o.annotation() + "가 붙은 요청 처리 메서드에서 "
                    + (o.container() == null ? "요청 맵" : "요청 맵의 " + o.container()) + "의 " + o.keys() + "를 세션 값으로 덮어씀"
                    + (o.requiredFirstParam() == null ? "" : "(첫 파라미터가 " + o.requiredFirstParam() + "일 때)"));
        }
        if (!effective.loginTypeNames().isEmpty()) {
            lines.add("로그인 정보 객체(추적 규칙 — 서버가 세션 등에서 꺼낸 값으로 봄): 타입 이름에 " + effective.loginTypeNames() + " 포함");
        }
        if (!effective.loginMethodPrefixes().isEmpty()) {
            lines.add("로그인 정보 getter(추적 규칙): " + effective.loginMethodPrefixes() + "로 시작하는 메서드");
        }
        if (!rules.authDevices(system).isEmpty()) {
            lines.add("인증 장치(추적 규칙 — 사람이 근거를 보고 로그인을 검사하고 막는다고 확인한 인터셉터·필터): " + rules.authDevices(system));
        }
        if (!effective.userScopeKeys().isEmpty()) {
            lines.add("사용자 범위 키(추적 규칙 — 회사·브랜드·사용자로 데이터를 가르는 값): " + effective.userScopeKeys());
        }
        return lines.stream()
                .limit(MAX_LINES)
                .map(line -> line.length() > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) + "…" : line)
                .map(line -> SecretMasker.mask(line).text())
                .toList();
    }
}
