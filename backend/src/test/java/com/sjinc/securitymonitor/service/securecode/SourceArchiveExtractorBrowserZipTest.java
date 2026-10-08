package com.sjinc.securitymonitor.service.securecode;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.CRC32;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 코드 점검 화면의 폴더 업로드가 만드는 zip(static/js/zip-writer.js — 무압축, 파일명 UTF-8 표시)을 서버가 푸는지.
 * 같은 바이트 배치를 여기서 그대로 만들어 넣는다(자바스크립트를 테스트에서 돌릴 수 없어서).
 */
class SourceArchiveExtractorBrowserZipTest {

    @TempDir
    Path dir;

    /** zip-writer.js storedBlob과 같은 배치: 로컬 헤더(30) + 이름 + 데이터 …, 중앙 디렉터리(46) + 이름 …, 끝(22). */
    private static byte[] storedZip(List<String[]> files) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        ByteArrayOutputStream central = new ByteArrayOutputStream();
        int offset = 0;
        for (String[] f : files) {
            byte[] name = f[0].getBytes(StandardCharsets.UTF_8);
            byte[] data = f[1].getBytes(StandardCharsets.UTF_8);
            CRC32 crc = new CRC32();
            crc.update(data);
            ByteBuffer local = ByteBuffer.allocate(30).order(ByteOrder.LITTLE_ENDIAN);
            local.putInt(0x04034b50).putShort((short) 20).putShort((short) 0x0800).putShort((short) 0)
                    .putShort((short) 0).putShort((short) 0x5821)
                    .putInt((int) crc.getValue()).putInt(data.length).putInt(data.length).putShort((short) name.length).putShort((short) 0);
            body.writeBytes(local.array());
            body.writeBytes(name);
            body.writeBytes(data);
            ByteBuffer entry = ByteBuffer.allocate(46).order(ByteOrder.LITTLE_ENDIAN);
            entry.putInt(0x02014b50).putShort((short) 20).putShort((short) 20).putShort((short) 0x0800).putShort((short) 0)
                    .putShort((short) 0).putShort((short) 0x5821)
                    .putInt((int) crc.getValue()).putInt(data.length).putInt(data.length).putShort((short) name.length)
                    .putShort((short) 0).putShort((short) 0).putShort((short) 0).putShort((short) 0).putInt(0).putInt(offset);
            central.writeBytes(entry.array());
            central.writeBytes(name);
            offset += 30 + name.length + data.length;
        }
        ByteBuffer end = ByteBuffer.allocate(22).order(ByteOrder.LITTLE_ENDIAN);
        end.putInt(0x06054b50).putShort((short) 0).putShort((short) 0).putShort((short) files.size()).putShort((short) files.size())
                .putInt(central.size()).putInt(offset).putShort((short) 0);
        body.writeBytes(central.toByteArray());
        body.writeBytes(end.array());
        return body.toByteArray();
    }

    @Test
    void 브라우저가_묶은_무압축_UTF8_zip을_풀고_폴더_이름을_벗긴다() throws Exception {
        Path zip = dir.resolve("legacy(폴더).zip");
        Files.write(zip, storedZip(List.of(
                new String[]{"legacy/src/com/a/A.java", "class A {}"},
                new String[]{"legacy/WebContent/화면/목록.jsp", "<%= request.getParameter(\"q\") %>"})));
        Path out = Files.createDirectories(dir.resolve("out"));

        SourceArchiveExtractor.Result result = SourceArchiveExtractor.extract(zip, out,
                new SourceArchiveExtractor.Limits(1_000_000, 100));

        assertThat(result.strippedRoot()).isEqualTo("legacy");
        assertThat(result.sourceFileCount()).isEqualTo(2);
        assertThat(out.resolve("WebContent/화면/목록.jsp")).hasContent("<%= request.getParameter(\"q\") %>");
    }
}
