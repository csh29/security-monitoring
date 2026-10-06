package com.sjinc.securitymonitor.service.maven;

import com.sjinc.securitymonitor.domain.VersionJump;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VersionJumpClassifierTest {

    @Test
    void 바뀐_자리로_패치_마이너_메이저를_가른다() {
        assertThat(VersionJumpClassifier.classify("3.2.1", "3.2.12")).isEqualTo(VersionJump.PATCH);
        assertThat(VersionJumpClassifier.classify("3.1.5", "3.2.12")).isEqualTo(VersionJump.MINOR);
        assertThat(VersionJumpClassifier.classify("2.7.18", "3.0.0")).isEqualTo(VersionJump.MAJOR);
    }

    @Test
    void 접미사가_붙은_버전도_숫자_자리로_본다() {
        assertThat(VersionJumpClassifier.classify("5.2.20.RELEASE", "5.3.18")).isEqualTo(VersionJump.MINOR);
        assertThat(VersionJumpClassifier.classify("4.1.100.Final", "4.1.118.Final")).isEqualTo(VersionJump.PATCH);
        assertThat(VersionJumpClassifier.classify("1.0-RC1", "1.0.1")).isEqualTo(VersionJump.PATCH);
    }

    @Test
    void 자리가_모자란_버전은_0으로_채운다() {
        assertThat(VersionJumpClassifier.classify("1.10", "1.10.1")).isEqualTo(VersionJump.PATCH);
        assertThat(VersionJumpClassifier.classify("1.9", "1.10")).isEqualTo(VersionJump.MINOR);
    }

    @Test
    void 캘린더_버전도_첫_자리가_바뀌면_메이저다() {
        assertThat(VersionJumpClassifier.classify("2022.0.4", "2023.0.3")).isEqualTo(VersionJump.MAJOR);
    }

    @Test
    void 낮추거나_그대로면_사람이_봐야_한다() {
        assertThat(VersionJumpClassifier.classify("3.2.12", "3.2.1")).isEqualTo(VersionJump.UNKNOWN);
        assertThat(VersionJumpClassifier.classify("3.2.1", "3.2.1")).isEqualTo(VersionJump.UNKNOWN);
        // 1.0 정식은 1.0-RC1보다 높다 — 숫자 자리만 보면 "그대로"로 오판한다.
        assertThat(VersionJumpClassifier.classify("1.0", "1.0-RC1")).isEqualTo(VersionJump.UNKNOWN);
    }

    @Test
    void 해석할_수_없는_버전은_UNKNOWN() {
        assertThat(VersionJumpClassifier.classify("${spring.version}", "6.1.0")).isEqualTo(VersionJump.UNKNOWN);
        assertThat(VersionJumpClassifier.classify(null, "6.1.0")).isEqualTo(VersionJump.UNKNOWN);
        assertThat(VersionJumpClassifier.classify("6.0.0", "")).isEqualTo(VersionJump.UNKNOWN);
    }
}
