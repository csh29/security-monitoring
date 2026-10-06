package com.sjinc.securitymonitor.service.scan;

import com.sjinc.securitymonitor.dto.scan.SourceUsage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class SourceUsageExtractorTest {

    @Test
    void import_대상을_클래스_단위로_뽑는다() {
        String source = """
                package com.acme;

                import java.util.List;
                import static org.junit.jupiter.api.Assertions.assertEquals;
                import org.springframework.web.bind.annotation.*;
                import static org.mockito.Mockito.*;
                import java.util.List;
                // import com.fake.Commented; 는 줄 맨 앞이 import가 아니라 걸리지 않는다
                class Foo {}
                """;

        assertThat(SourceUsageExtractor.parseImports(source)).containsExactlyInAnyOrder(
                "java.util.List",
                "org.junit.jupiter.api.Assertions",       // static import는 멤버를 뗀 클래스
                "org.springframework.web.bind.annotation.*",
                "org.mockito.Mockito.*");
    }

    @Test
    void properties와_yml에서_키만_뽑고_값은_버린다() {
        assertThat(SourceUsageExtractor.parseConfigKeys("application.properties",
                "spring.datasource.password=secret\nserver.port=8080\n"))
                .containsExactlyInAnyOrder("spring.datasource.password", "server.port");

        String yml = """
                spring:
                  redis:
                    host: localhost
                    port: 6379
                server:
                  port: 8080
                ---
                management:
                  endpoints:
                    web:
                      exposure:
                        include: health
                """;
        assertThat(SourceUsageExtractor.parseConfigKeys("application-dev.yml", yml)).containsExactlyInAnyOrder(
                "spring.redis.host", "spring.redis.port", "server.port", "management.endpoints.web.exposure.include");
    }

    @Test
    void 형식이_깨진_설정_파일은_그_파일만_건너뛴다() {
        assertThat(SourceUsageExtractor.parseConfigKeys("application.yml", "spring: [unclosed")).isEmpty();
    }

    @Test
    void 빌드_산출물_폴더는_세지_않고_import는_파일_수로_센다(@TempDir Path dir) throws Exception {
        write(dir.resolve("src/main/java/com/acme/A.java"), "import java.util.List;\nimport java.util.List;\nclass A{}");
        write(dir.resolve("src/main/java/com/acme/B.java"), "import java.util.List;\nclass B{}");
        write(dir.resolve("target/generated/C.java"), "import java.util.List;\nclass C{}");
        write(dir.resolve("src/main/resources/application.properties"), "server.port=8080");
        write(dir.resolve("src/main/resources/other.properties"), "not.a.boot.key=1");

        SourceUsage usage = new SourceUsageExtractor().extract(dir);

        assertThat(usage.javaFileCount()).isEqualTo(2);
        assertThat(usage.imports()).containsEntry("java.util.List", 2);
        assertThat(usage.configKeys()).containsExactly("server.port");
    }

    private static void write(Path path, String content) throws Exception {
        Files.createDirectories(path.getParent());
        Files.writeString(path, content);
    }
}
