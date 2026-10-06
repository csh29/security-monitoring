package com.sjinc.cvemonitor.service.securecode;

import java.util.List;

/**
 * MyBatis {@code ${}} 한 곳의 값 출처 판정(MybatisDollarTracer).
 *
 * @param path      저장소 루트 기준 매퍼 XML 경로(구분자 /)
 * @param line      {@code ${}}가 있는 줄
 * @param statement 판정에 쓴 구문 id(조각이면 그 조각을 include한 구문들 중 가장 나쁜 것)
 * @param expr      {@code ${}} 안의 식
 * @param key       값을 꺼내는 파라미터 키
 * @param safety    판정
 * @param evidence  판정 근거 — 값이 지나온 길을 위에서부터(호출 쪽 → 매퍼 쪽) 한 줄씩
 */
public record DollarVerdict(String path, int line, String statement, String expr, String key,
                            Safety safety, List<String> evidence) {

    /** 위험한 것부터. 여러 경로가 있으면 가장 위험한 경로로 판정한다(rank가 클수록 위험). */
    public enum Safety {
        /** XML 안에서 값이 정해진다(bind 상수, 상수 비교 if 안). 어느 경로로 와도 안전. */
        XML_FIXED("XML에서 결정", 0),
        /** 세션 값으로 덮어쓴다(@AddUserInfo 등). 공통 실행 경로로 와도 덮어써져 안전. */
        SESSION_OVERWRITE("세션 값으로 덮어씀", 1),
        /** 모든 경로에서 서버가 상수·로그인 정보로 세팅한다. */
        SERVER_SET("서버가 세팅", 2),
        /** 출처를 끝까지 따라가지 못했다 — 사람이 확인한다. */
        UNKNOWN("판정 불가", 3),
        /** 서비스 경로에서는 서버가 세팅하지만, 클라이언트가 구문 id를 정하는 공통 실행 경로로 직접 부르면 클라이언트 값이 들어간다. */
        BYPASSABLE("공통 경로로 우회 가능", 4),
        /** 클라이언트가 보낸 값이 그대로 들어간다(조건부 세팅으로 원래 값이 남는 경우 포함). */
        CLIENT("클라이언트 값", 5);

        private final String label;
        private final int rank;

        Safety(String label, int rank) {
            this.label = label;
            this.rank = rank;
        }

        public String label() {
            return label;
        }

        public boolean worseThan(Safety other) {
            return rank > other.rank;
        }

        /** 사람이 볼 필요가 없을 만큼 안전한가. */
        public boolean isSafe() {
            return rank <= SERVER_SET.rank;
        }
    }
}
