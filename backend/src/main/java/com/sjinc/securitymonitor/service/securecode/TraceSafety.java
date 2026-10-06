package com.sjinc.securitymonitor.service.securecode;

/**
 * 연계 추적 판정 — 값이 어디서 오는가. MyBatis {@code ${}}(MybatisDollarTracer)와 위험 호출 지점(SinkTracer)이 함께 쓴다.
 * 위험한 것부터 rank가 크다. 여러 경로가 있으면 가장 위험한 경로로 판정한다.
 */
public enum TraceSafety {
    /** XML 안에서 값이 정해진다(bind 상수, 상수 비교 if 안). 어느 경로로 와도 안전. */
    XML_FIXED("XML에서 결정", 0),
    /** 세션 값으로 덮어쓴다(@AddUserInfo 등). 공통 실행 경로로 와도 덮어써져 안전. */
    SESSION_OVERWRITE("세션 값으로 덮어씀", 1),
    /** 모든 경로에서 서버가 상수·로그인 정보·설정값으로 정한다. */
    SERVER_SET("서버가 세팅", 2),
    /** 출처를 끝까지 따라가지 못했다 — 사람이 확인한다. */
    UNKNOWN("판정 불가", 3),
    /** 서비스 경로에서는 서버가 세팅하지만, 클라이언트가 구문 id를 정하는 공통 실행 경로로 직접 부르면 클라이언트 값이 들어간다. */
    BYPASSABLE("공통 경로로 우회 가능", 4),
    /** 클라이언트가 보낸 값이 그대로 들어간다(조건부 세팅으로 원래 값이 남는 경우 포함). */
    CLIENT("클라이언트 값", 5);

    private final String label;
    private final int rank;

    TraceSafety(String label, int rank) {
        this.label = label;
        this.rank = rank;
    }

    public String label() {
        return label;
    }

    public boolean worseThan(TraceSafety other) {
        return rank > other.rank;
    }

    /** 사람이 볼 필요가 없을 만큼 안전한가. */
    public boolean isSafe() {
        return rank <= SERVER_SET.rank;
    }

    /**
     * 이 판정으로 다시 매긴 심각도(공통코드 SEVERITY). 클라이언트 값·우회 가능은 실제로 공격 가능해 HIGH(WARNING 규칙이면 올린다),
     * 판정 불가는 사람 검토라 MEDIUM, 안전 판정은 LOW. 안전해도 자동으로 오탐 처리하지는 않는다.
     */
    public String severity() {
        if (this == CLIENT || this == BYPASSABLE) return "HIGH";
        if (this == UNKNOWN) return "MEDIUM";
        return "LOW";
    }
}
