package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.dto.ai.FixPlanRequest.Change;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FixPlanServiceTest {

    private static Change change(String coordinate, String from, String to, String via) {
        return new Change(coordinate, null, from, to, via);
    }

    @Test
    void 형식이_맞는_변경만_남긴다() {
        Change ok = change("org.springframework.boot:spring-boot-starter-parent", "3.1.5", "3.2.12", "PARENT");
        List<Change> requested = Arrays.asList(
                ok,
                change("spring-boot-starter-parent", "3.1.5", "3.2.12", "PARENT"), // groupId 누락
                change("io.netty:netty-codec", "", "4.1.118.Final", "PROPERTY"),    // from 없음
                change("io.netty:netty-codec", "4.1.100.Final", "4.1.118.Final", "OVERRIDE"), // 정해지지 않은 via
                change("a b:c", "1.0", "1.1", "DIRECT"),                           // 공백 포함 좌표
                null);

        assertThat(FixPlanService.validChanges(requested)).containsExactly(ok);
    }

    @Test
    void 변경_목록을_안_보내는_예전_배치도_받아준다() {
        assertThat(FixPlanService.validChanges(null)).isEmpty();
    }
}
