package com.sjinc.cvemonitor.domain;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * 심각도(공통코드 SEVERITY 값) 정렬 순서 — 취약점 관리와 코드 점검 결과가 같은 기준으로 "높은 것부터" 보이게 한다.
 * 문자열 그대로 정렬하면 CRITICAL, HIGH, LOW, MEDIUM(알파벳순)이 되어 LOW가 MEDIUM보다 위에 온다.
 */
public final class SeverityOrder {

    /** 높은 것부터. 목록에 없는 값(빈 값·예전 데이터)은 맨 뒤로 보낸다 — 판단할 수 없는 건이 위험한 건 사이에 끼지 않게. */
    private static final List<String> HIGH_TO_LOW = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    /** 심각도가 높은 것이 먼저 오는 비교기. */
    public static final Comparator<String> HIGH_FIRST = Comparator.comparingInt(SeverityOrder::rank);

    private SeverityOrder() {
    }

    static int rank(String severity) {
        int index = severity == null ? -1 : HIGH_TO_LOW.indexOf(severity.toUpperCase(Locale.ROOT));
        return index < 0 ? HIGH_TO_LOW.size() : index;
    }
}
