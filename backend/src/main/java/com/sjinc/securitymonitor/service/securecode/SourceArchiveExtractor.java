package com.sjinc.securitymonitor.service.securecode;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

/**
 * 업로드한 소스 zip을 점검용 임시 폴더에 풀기만 한다(실행은 하지 않는다). Zip Slip 항목이 하나라도 있으면 전체를 거부하고,
 * 항목 수·실제 풀린 바이트에 상한을 두며, 심볼릭 링크는 일반 파일로 써서 서버 파일을 가리킬 수 없다. 이름은 UTF-8이 깨지면 MS949로 읽는다.
 * 지문이 저장소 기준 경로라 올릴 때마다 경로가 달라지지 않게, 항목이 전부 한 최상위 폴더 아래면 그 폴더를 벗긴다.
 */
public final class SourceArchiveExtractor {

    /**
     * @param maxExtractedBytes 풀린 파일 크기의 합 상한
     * @param maxEntries        파일 항목 수 상한
     */
    public record Limits(long maxExtractedBytes, int maxEntries) {
    }

    /**
     * @param fileCount       푼 파일 수
     * @param sourceFileCount 점검 대상 확장자 파일 수 — 0이면 점검할 게 없다(서비스가 거부한다)
     * @param strippedRoot    벗긴 최상위 폴더 이름(없으면 null)
     */
    public record Result(int fileCount, int sourceFileCount, String strippedRoot) {
    }

    /**
     * 코드 점검 규칙이 보는 확장자(하나도 없는 zip은 소스가 아니다). 화면의 폴더 업로드(secure-code-scan.html)도
     * 같은 목록을 쓰므로 두 곳을 같이 고친다.
     */
    static final Set<String> SOURCE_EXTENSIONS = Set.of(
            "java", "jsp", "jspx", "jspf", "xml", "properties", "yml", "yaml",
            "js", "jsx", "ts", "tsx", "vue", "html", "htm");

    private static final Charset MS949 = Charset.forName("MS949");

    private SourceArchiveExtractor() {
    }

    public static Result extract(Path zip, Path target, Limits limits) throws IOException {
        Charset charset;
        List<String> names;
        try {
            names = fileNames(zip, StandardCharsets.UTF_8);
            charset = StandardCharsets.UTF_8;
        } catch (IllegalArgumentException | ZipException e) {
            // 이름이 UTF-8이 아니다(ZipFile은 깨진 이름에서 IllegalArgumentException("MALFORMED")을 던진다).
            try {
                names = fileNames(zip, MS949);
            } catch (ZipException notZip) {
                throw new IllegalArgumentException("zip 파일을 읽지 못했습니다(손상되었거나 암호가 걸린 zip일 수 있습니다).");
            }
            charset = MS949;
        }
        if (names.size() > limits.maxEntries()) {
            throw new IllegalArgumentException("zip 안의 파일이 너무 많습니다(" + names.size() + "개, 최대 " + limits.maxEntries() + "개).");
        }
        // 하나라도 밖을 가리키면 아무것도 풀기 전에 거부한다. 최상위 폴더를 벗기기 전 원래 이름으로 본다 — "C:/Windows/a.java"는
        // 벗기면 "Windows/a.java"로 보여 통과한다.
        for (String name : names) {
            safeRelative(name);
        }
        String root = commonRoot(names);

        Path base = target.toAbsolutePath().normalize();
        long written = 0;
        int files = 0, sources = 0;
        try (ZipFile zipFile = new ZipFile(zip.toFile(), charset)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || isJunk(entry.getName())) continue;
                String relative = safeRelative(strip(entry.getName(), root));
                if (relative.isEmpty()) continue;
                Path out = base.resolve(relative).normalize();
                if (!out.startsWith(base)) {
                    throw new IllegalArgumentException("zip 안에 점검 폴더 밖을 가리키는 경로가 있습니다: " + entry.getName());
                }
                Files.createDirectories(out.getParent());
                try (InputStream in = zipFile.getInputStream(entry); OutputStream os = Files.newOutputStream(out)) {
                    byte[] buffer = new byte[64 * 1024];
                    int n;
                    while ((n = in.read(buffer)) > 0) {
                        written += n;
                        if (written > limits.maxExtractedBytes()) {
                            throw new IllegalArgumentException("압축을 푼 크기가 너무 큽니다(최대 "
                                    + limits.maxExtractedBytes() / (1024 * 1024) + "MB).");
                        }
                        os.write(buffer, 0, n);
                    }
                }
                files++;
                if (SOURCE_EXTENSIONS.contains(extension(relative))) sources++;
            }
        } catch (ZipException e) {
            throw new IllegalArgumentException("zip 파일을 읽지 못했습니다(손상되었거나 암호가 걸린 zip일 수 있습니다).");
        }
        return new Result(files, sources, root);
    }

    /** 파일 항목 이름들(폴더·OS 부산물 제외). charset으로 이름을 못 읽으면 예외. */
    private static List<String> fileNames(Path zip, Charset charset) throws IOException {
        List<String> names = new ArrayList<>();
        try (ZipFile zipFile = new ZipFile(zip.toFile(), charset)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (!entry.isDirectory() && !isJunk(entry.getName())) names.add(entry.getName());
            }
        }
        return names;
    }

    /** macOS 압축이 넣는 리소스 포크(__MACOSX/, ._파일) — 소스가 아니고 Semgrep이 해석하지 못해 "분석 실패"로 잡힌다. */
    private static boolean isJunk(String name) {
        String normalized = name.replace('\\', '/');
        String base = normalized.substring(normalized.lastIndexOf('/') + 1);
        return normalized.startsWith("__MACOSX/") || base.startsWith("._");
    }

    /** 모든 항목이 같은 최상위 폴더 아래면 그 이름, 아니면 null. 파일이 최상위에 바로 있으면 벗기지 않는다. */
    static String commonRoot(List<String> names) {
        String root = null;
        for (String name : names) {
            String normalized = name.replace('\\', '/');
            int slash = normalized.indexOf('/');
            if (slash <= 0) return null;
            String first = normalized.substring(0, slash);
            if (root == null) root = first;
            else if (!root.equals(first)) return null;
        }
        return root;
    }

    private static String strip(String name, String root) {
        String normalized = name.replace('\\', '/');
        return root == null ? normalized : normalized.substring(root.length() + 1);
    }

    /** 대상 폴더 기준 상대 경로. 절대 경로·드라이브 문자·".." 조각이 있으면 거부한다. */
    static String safeRelative(String path) {
        String p = path.replace('\\', '/');
        if (p.startsWith("/") || p.matches("^[A-Za-z]:.*")) {
            throw new IllegalArgumentException("zip 안에 절대 경로 항목이 있습니다: " + path);
        }
        for (String part : p.split("/")) {
            if (part.equals("..")) {
                throw new IllegalArgumentException("zip 안에 점검 폴더 밖을 가리키는 경로가 있습니다: " + path);
            }
        }
        return p;
    }

    private static String extension(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "" : path.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
