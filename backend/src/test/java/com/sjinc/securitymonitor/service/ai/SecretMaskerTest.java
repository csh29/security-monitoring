package com.sjinc.securitymonitor.service.ai;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretMaskerTest {

    // 토큰 형식 값을 소스에 그대로 두면 저장소 비밀값 검사(GitHub push protection 등)가 진짜 토큰으로 보고 막는다 — 조각을 이어 만든다.
    private static final String GITHUB_TOKEN = "ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789";
    private static final String AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP";

    private static final String POM = """
            <project>
              <properties>
                <java.version>17</java.version>
                <db.password>p@ss-W0rd!</db.password>
                <jasypt.encryptor.password>${JASYPT_KEY}</jasypt.encryptor.password>
                <github.token>%s</github.token>
              </properties>
              <repositories>
                <repository><url>https://deploy:s3cret@nexus.sjinc.co.kr/repository/maven-public/</url></repository>
              </repositories>
              <build><plugins><plugin>
                <configuration>
                  <url>jdbc:postgresql://db:5432/crm?user=crm&amp;password=dbpass123</url>
                  <storepass>changeit</storepass>
                  <arg>-Daws.accessKeyId=%s</arg>
                </configuration>
              </plugin></plugins></build>
              <dependencies><dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-crypto</artifactId><version>6.3.1</version></dependency></dependencies>
            </project>
            """.formatted(GITHUB_TOKEN, AWS_KEY);

    @Test
    void 비밀값만_가리고_버전_좌표_프로퍼티_참조는_남긴다() {
        SecretMasker.Masked masked = SecretMasker.mask(POM);

        assertThat(masked.text())
                .doesNotContain("p@ss-W0rd!", GITHUB_TOKEN, "deploy:s3cret", "dbpass123",
                        "changeit", AWS_KEY)
                .contains("<java.version>17</java.version>", "<version>6.3.1</version>", "spring-security-crypto",
                        "${JASYPT_KEY}", "@nexus.sjinc.co.kr/", "<db.password>__MASKED_SECRET_");
        assertThat(masked.secrets()).containsValues("p@ss-W0rd!", "deploy:s3cret", "dbpass123", "changeit");
    }

    @Test
    void AI가_고친_pom의_자리표시자를_되돌린다() {
        SecretMasker.Masked masked = SecretMasker.mask(POM);
        String aiResult = masked.text().replace("<version>6.3.1</version>", "<version>6.3.4</version>");

        SecretMasker.Unmasked restored = SecretMasker.unmask(aiResult, SecretMasker.mask(POM).secrets());

        assertThat(restored.remainingPlaceholders()).isZero();
        assertThat(restored.text()).isEqualTo(POM.replace("<version>6.3.1</version>", "<version>6.3.4</version>"));
    }

    @Test
    void 보낸_뒤_pom이_바뀌었으면_되돌리지_않고_자리표시자를_남긴다() {
        SecretMasker.Masked sent = SecretMasker.mask(POM);
        String changedPom = POM.replace("p@ss-W0rd!", "other-pass").replace("<java.version>17", "<java.version>21");

        SecretMasker.Unmasked restored = SecretMasker.unmask(sent.text(), SecretMasker.mask(changedPom).secrets());

        assertThat(restored.remainingPlaceholders()).isEqualTo(sent.secrets().size());
        assertThat(restored.text()).doesNotContain("other-pass").contains("__MASKED_SECRET_");
    }

    @Test
    void 비밀값이_없으면_원문_그대로() {
        String pom = "<project><version>1.0</version></project>";
        assertThat(SecretMasker.mask(pom).text()).isEqualTo(pom);
        assertThat(SecretMasker.mask(null).text()).isNull();
    }
}
