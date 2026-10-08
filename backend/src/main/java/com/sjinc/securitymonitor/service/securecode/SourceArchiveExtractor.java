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
 * 업로드한 소스 zip을 점검용 임시 폴더에 푼다(Git으로 접근할 수 없는 앱 — App.SOURCE_UPLOAD). Spring 없이 테스트할 수 있게 순수 클래스로 둔다.
 *
 * <p>외부에서 받은 압축 파일을 서버에 푸는 일이라 다음을 막는다.
 * <ul>
 *   <li>경로 조작(Zip Slip) — {@code ../}·절대 경로·드라이브 문자로 대상 폴더 밖에 쓰려는 항목이 하나라도 있으면 업로드 전체를 거부한다
 *       (정상적인 소스 압축에는 없다 — 일부만 건너뛰면 "조작된 zip"을 점검 결과로 받아들이게 된다).</li>
 *   <li>압축 폭탄 — 항목 수와 실제로 풀린 총 바이트(헤더에 적힌 크기가 아니라 쓰면서 센 값)에 상한을 둔다.</li>
 *   <li>심볼릭 링크 — ZipFile은 링크를 만들지 않고 일반 파일로 쓴다(링크 대상 경로 문자열이 내용이 된다). 서버 파일을 가리킬 수 없다.</li>
 * </ul>
 * 압축을 풀기만 하고 아무것도 실행하지 않는다 — 코드 점검은 소스를 읽기만 한다(Semgrep·JavaParser).
 *
 * <p>Windows 탐색기로 만든 zip은 한글 파일명이 MS949로 들어 있는 경우가 많다(UTF-8 표시 없이). UTF-8로 읽다 깨지면 MS949로 다시 읽는다
 * (SecureCodeSnippetBuilder가 소스 내용을 읽는 방식과 같다).
 *
 * <p>항목이 전부 한 최상위 폴더 아래에 있으면(프로젝트 폴더째 압축한 경우) 그 폴더를 벗긴다 — 탐지 지문이 저장소 기준 경로로 만들어져,
 * "myapp/src/..."와 "src/..."로 올릴 때마다 경로가 달라지면 재점검에서 모든 탐지가 "해결+신규"로 바뀐다.
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
     * 코드 점검 규칙이 보는 확장자. 이게 하나도 없는 zip은 소스가 아니다. 코드 점검 화면의 폴더 업로드(secure-code-scan.html
     * SOURCE_EXTENSIONS)가 이 목록으로 묶을 파일을 고른다 — 규칙이 새 확장자를 보게 되면 두 곳을 같이 고친다.
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
