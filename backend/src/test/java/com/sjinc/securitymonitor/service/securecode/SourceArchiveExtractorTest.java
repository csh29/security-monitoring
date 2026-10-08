package com.sjinc.securitymonitor.service.securecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SourceArchiveExtractorTest {

    private static final SourceArchiveExtractor.Limits LIMITS = new SourceArchiveExtractor.Limits(10 * 1024 * 1024, 1000);

    @TempDir
    Path dir;

    private Path zip(Map<String, String> entries, Charset charset) throws IOException {
        Path zip = dir.resolve("src-" + System.nanoTime() + ".zip");
        try (OutputStream out = Files.newOutputStream(zip); ZipOutputStream zos = new ZipOutputStream(out, charset)) {
            for (Map.Entry<String, String> e : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return zip;
    }

    private Path zip(Map<String, String> entries) throws IOException {
        return zip(entries, StandardCharsets.UTF_8);
    }

    private Path target() throws IOException {
        return Files.createDirectories(dir.resolve("out-" + System.nanoTime()));
    }

    @Test
    void 프로젝트_폴더째_압축하면_최상위_폴더를_벗기고_소스_파일을_센다() throws Exception {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("myapp/src/main/java/A.java", "class A {}");
        entries.put("myapp/src/main/resources/mapper/a.xml", "<mapper/>");
        entries.put("myapp/README.md", "readme");
        Path out = target();

        SourceArchiveExtractor.Result result = SourceArchiveExtractor.extract(zip(entries), out, LIMITS);

        // 지문이 저장소 기준 경로로 만들어져, 올릴 때마다 최상위 폴더 이름이 달라도 경로가 같아야 재점검 비교가 된다
        assertThat(result.strippedRoot()).isEqualTo("myapp");
        assertThat(out.resolve("src/main/java/A.java")).hasContent("class A {}");
        assertThat(result.fileCount()).isEqualTo(3);
        assertThat(result.sourceFileCount()).isEqualTo(2);
    }

    @Test
    void 최상위에_파일이_섞여_있으면_벗기지_않는다() throws Exception {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("pom.xml", "<project/>");
        entries.put("src/A.java", "class A {}");

        SourceArchiveExtractor.Result result = SourceArchiveExtractor.extract(zip(entries), target(), LIMITS);

        assertThat(result.strippedRoot()).isNull();
    }

    @Test
    void 폴더_밖을_가리키는_항목이_하나라도_있으면_아무것도_풀지_않고_거부한다() throws Exception {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("src/A.java", "class A {}");
        entries.put("../../evil.jsp", "<% %>");
        Path out = target();

        assertThatThrownBy(() -> SourceArchiveExtractor.extract(zip(entries), out, LIMITS))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("밖을 가리키는");
        assertThat(out.resolve("src/A.java")).doesNotExist();
        assertThat(dir.getParent().resolve("evil.jsp")).doesNotExist();
    }

    @Test
    void 절대_경로_항목도_거부한다() throws Exception {
        assertThatThrownBy(() -> SourceArchiveExtractor.extract(zip(Map.of("/etc/passwd.xml", "x")), target(), LIMITS))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("절대 경로");
        assertThatThrownBy(() -> SourceArchiveExtractor.extract(zip(Map.of("C:/Windows/a.java", "x")), target(), LIMITS))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("절대 경로");
    }

    @Test
    void 풀린_크기와_항목_수에_상한이_있다() throws Exception {
        Path big = zip(Map.of("src/A.java", "x".repeat(5000)));
        assertThatThrownBy(() -> SourceArchiveExtractor.extract(big, target(), new SourceArchiveExtractor.Limits(1000, 1000)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("너무 큽니다");

        Map<String, String> many = new LinkedHashMap<>();
        for (int i = 0; i < 6; i++) many.put("src/A" + i + ".java", "x");
        assertThatThrownBy(() -> SourceArchiveExtractor.extract(zip(many), target(), new SourceArchiveExtractor.Limits(1_000_000, 5)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("너무 많습니다");
    }

    @Test
    void 윈도우에서_만든_MS949_한글_파일명도_읽는다() throws Exception {
        Path ms949 = zip(Map.of("소스/화면.jsp", "<%= x %>"), Charset.forName("MS949"));
        Path out = target();

        SourceArchiveExtractor.Result result = SourceArchiveExtractor.extract(ms949, out, LIMITS);

        assertThat(result.strippedRoot()).isEqualTo("소스");
        assertThat(out.resolve("화면.jsp")).exists();
    }

    @Test
    void 맥_압축_부산물은_건너뛰고_소스가_없으면_0개로_센다() throws Exception {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("app/__MACOSX/._A.java", "junk");
        entries.put("app/._B.java", "junk");
        entries.put("app/docs/manual.pdf", "pdf");

        SourceArchiveExtractor.Result result = SourceArchiveExtractor.extract(zip(entries), target(), LIMITS);

        assertThat(result.fileCount()).isEqualTo(1);
        assertThat(result.sourceFileCount()).isZero();
    }

    @Test
    void zip이_아니면_읽지_못했다고_알린다() throws Exception {
        Path notZip = dir.resolve("a.zip");
        Files.writeString(notZip, "not a zip");

        assertThatThrownBy(() -> SourceArchiveExtractor.extract(notZip, target(), LIMITS))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("zip 파일을 읽지 못했습니다");
    }
}
