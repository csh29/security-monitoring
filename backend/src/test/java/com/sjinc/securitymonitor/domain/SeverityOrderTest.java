package com.sjinc.securitymonitor.domain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SeverityOrderTest {

    @Test
    void 높은_심각도부터_정렬하고_알파벳순이_아니다() {
        List<String> severities = new ArrayList<>(List.of("LOW", "MEDIUM", "CRITICAL", "HIGH"));

        severities.sort(SeverityOrder.HIGH_FIRST);

        // 문자열 정렬이면 LOW가 MEDIUM보다 앞에 온다.
        assertThat(severities).containsExactly("CRITICAL", "HIGH", "MEDIUM", "LOW");
    }

    @Test
    void 모르는_값과_빈_값은_맨_뒤로_보내고_대소문자는_가리지_않는다() {
        List<String> severities = new ArrayList<>(Arrays.asList(null, "UNKNOWN", "low", "high"));

        severities.sort(SeverityOrder.HIGH_FIRST);

        assertThat(severities.subList(0, 2)).containsExactly("high", "low");
        assertThat(severities.subList(2, 4)).containsExactlyInAnyOrder(null, "UNKNOWN");
    }
}
