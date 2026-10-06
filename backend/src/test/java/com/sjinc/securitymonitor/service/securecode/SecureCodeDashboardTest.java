package com.sjinc.securitymonitor.service.securecode;

import com.sjinc.securitymonitor.dto.securecode.SecureCodeDashboard;
import com.sjinc.securitymonitor.dto.securecode.SecureCodeStatusCount;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecureCodeDashboardTest {

    @Test
    void 미조치_건수와_HIGH_비율_처리율을_계산한다() {
        SecureCodeDashboard dashboard = SecureCodeFindingService.summarize(List.of(
                new SecureCodeStatusCount("OPEN", "HIGH", 3),
                new SecureCodeStatusCount("OPEN", "MEDIUM", 1),
                new SecureCodeStatusCount("FALSE_POSITIVE", "HIGH", 4),
                new SecureCodeStatusCount("RESOLVED", "MEDIUM", 2)), List.of());

        assertThat(dashboard.openCount()).isEqualTo(4);
        assertThat(dashboard.openHighRate()).isEqualTo(75);   // 미조치 4건 중 HIGH 3건
        assertThat(dashboard.handledRate()).isEqualTo(60);    // 전체 10건 중 처리 6건(오탐 4 + 조치완료 2)
        assertThat(dashboard.scanned()).isTrue();
    }

    @Test
    void 탐지가_없으면_점검_전으로_표시한다() {
        SecureCodeDashboard dashboard = SecureCodeFindingService.summarize(List.of(), List.of());

        // 처리율을 100%로 내면 점검을 안 한 상태가 "다 고쳤다"로 읽힌다.
        assertThat(dashboard.scanned()).isFalse();
        assertThat(dashboard.openCount()).isZero();
    }

    @Test
    void 전부_처리했으면_미조치_HIGH_비율은_0_처리율은_100() {
        SecureCodeDashboard dashboard = SecureCodeFindingService.summarize(List.of(
                new SecureCodeStatusCount("ACCEPTED", "HIGH", 2)), List.of());

        assertThat(dashboard.openHighRate()).isZero();
        assertThat(dashboard.handledRate()).isEqualTo(100);
        assertThat(dashboard.scanned()).isTrue();
    }
}
