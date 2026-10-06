package com.sjinc.securitymonitor.service.osv;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.dto.osv.OsvVulnDetail;
import com.sjinc.securitymonitor.service.osv.OsvFixVersionResolver.Resolution;
import com.sjinc.securitymonitor.service.osv.OsvFixVersionResolver.Status;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OsvFixVersionResolverTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 실제로 겪은 케이스를 그대로 재현한다: pgjdbc 42.7.2가 CVE-2026-42198에 걸려 42.7.11로
     * 올리라고 제안됐는데, 42.7.11 자체가 CVE-2026-54291(42.7.4~42.7.11 영향, 42.7.12에서
     * 수정)에 걸려있다. 42.7.12는 깨끗해야 한다.
     */
    @Test
    void 제안된_버전_자체가_다른_CVE에_걸려있으면_한번_더_올라간다() throws Exception {
        OsvClient osvClient = mock(OsvClient.class);
        when(osvClient.queryVersion("org.postgresql", "postgresql", "42.7.11"))
                .thenReturn(List.of(vulnDetail("org.postgresql:postgresql", "42.7.4", "42.7.12")));
        when(osvClient.queryVersion("org.postgresql", "postgresql", "42.7.12"))
                .thenReturn(List.of());

        Resolution resolution = new OsvFixVersionResolver(osvClient)
                .resolve("org.postgresql", "postgresql", "42.7.11");

        assertThat(resolution.finalVersion()).isEqualTo("42.7.12");
        assertThat(resolution.status()).isEqualTo(Status.CLEAN);
        assertThat(resolution.chain()).containsExactly("42.7.11", "42.7.12");
    }

    @Test
    void 처음부터_깨끗하면_그대로_돌려준다() {
        OsvClient osvClient = mock(OsvClient.class);
        when(osvClient.queryVersion("com.example", "lib", "2.0.0")).thenReturn(List.of());

        Resolution resolution = new OsvFixVersionResolver(osvClient).resolve("com.example", "lib", "2.0.0");

        assertThat(resolution.finalVersion()).isEqualTo("2.0.0");
        assertThat(resolution.isClean()).isTrue();
        assertThat(resolution.chain()).containsExactly("2.0.0");
    }

    @Test
    void 같은_메이저_라인에_수정버전이_없으면_자동으로_더_올리지_않는다() throws Exception {
        OsvClient osvClient = mock(OsvClient.class);
        // 남은 취약점의 수정 버전이 3.x(메이저 업그레이드)뿐이고, 2.x 라인엔 없다.
        when(osvClient.queryVersion("com.example", "lib", "2.5.0"))
                .thenReturn(List.of(vulnDetail("com.example:lib", "2.0.0", "3.0.0")));

        Resolution resolution = new OsvFixVersionResolver(osvClient).resolve("com.example", "lib", "2.5.0");

        assertThat(resolution.finalVersion()).isEqualTo("2.5.0");
        assertThat(resolution.status()).isEqualTo(Status.NO_SAME_LINE_FIX);
    }

    @Test
    void 무한루프_없이_최대_깊이에서_멈춘다() {
        OsvClient osvClient = mock(OsvClient.class);
        for (int i = 0; i < 10; i++) {
            String from = "1." + i + ".0";
            String to = "1." + (i + 1) + ".0";
            try {
                when(osvClient.queryVersion("com.example", "lib", from))
                        .thenReturn(List.of(vulnDetail("com.example:lib", "1.0.0", to)));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        Resolution resolution = new OsvFixVersionResolver(osvClient).resolve("com.example", "lib", "1.0.0");

        assertThat(resolution.status()).isEqualTo(Status.MAX_DEPTH_REACHED);
        assertThat(resolution.chain()).hasSize(5); // MAX_DEPTH
    }

    @Test
    void 다른_패키지의_수정버전_번호는_섞이지_않는다() throws Exception {
        OsvClient osvClient = mock(OsvClient.class);
        // 하나의 취약점 공지가 여러 패키지를 함께 다루는 경우 — 엉뚱한 패키지의 fixed 버전을 주워오면 안 된다.
        String json = """
                {
                  "id": "GHSA-multi",
                  "affected": [
                    {"package": {"name": "com.other:lib", "ecosystem": "Maven"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
                    {"package": {"name": "com.example:lib", "ecosystem": "Maven"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}]}
                  ]
                }
                """;
        OsvVulnDetail detail = MAPPER.readValue(json, OsvVulnDetail.class);
        when(osvClient.queryVersion("com.example", "lib", "2.0.0")).thenReturn(List.of(detail));
        when(osvClient.queryVersion("com.example", "lib", "2.1.0")).thenReturn(List.of());

        Resolution resolution = new OsvFixVersionResolver(osvClient).resolve("com.example", "lib", "2.0.0");

        assertThat(resolution.finalVersion()).isEqualTo("2.1.0");
    }

    private OsvVulnDetail vulnDetail(String packageName, String introduced, String fixed) throws Exception {
        String json = """
                {
                  "id": "GHSA-test",
                  "affected": [
                    {"package": {"name": "%s", "ecosystem": "Maven"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "%s"}, {"fixed": "%s"}]}]}
                  ]
                }
                """.formatted(packageName, introduced, fixed);
        return MAPPER.readValue(json, OsvVulnDetail.class);
    }
}
