package com.sjinc.securitymonitor.service.scan;

import com.sjinc.securitymonitor.dto.scan.SourceUsage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * clone한 저장소에서 import 문과 설정 키를 뽑는다. 스캔이 끝나면 clone 디렉터리는 지워지므로 그 전에 부른다.
 *
 * <p>정규식으로 import 줄만 읽는다 — 컴파일도 파싱도 하지 않으므로 빠르고, 빌드가 안 되는 저장소에서도 동작한다.
 * 그만큼 import 없이 전체 이름으로 쓰거나 리플렉션·XML 설정으로 쓰는 경우는 못 잡는다(CodeUsageMatcher가 "안 보임"을
 * "영향 없음"으로 말하지 않는 이유).
 */
@Slf4j
@Component
public class SourceUsageExtractor {

    /** 이보다 큰 파일은 생성 코드이거나 소스가 아닐 가능성이 커서 건너뛴다(스캔 시간 보호). */
    private static final long MAX_FILE_BYTES = 1_000_000;

    private static final Pattern IMPORT = Pattern.compile(
            "^\\s*import\\s+(static\\s+)?([\\w.]+?)(\\.\\*)?\\s*;", Pattern.MULTILINE);

    /** 파일 경로의 어느 부분이라도 이 이름이면 건너뛴다 — 빌드 산출물·IDE 폴더의 사본을 중복으로 세지 않기 위함. */
    private static final Set<String> SKIP_DIRS = Set.of("target", "build", ".git", ".idea", "node_modules", "out");

    public SourceUsage extract(Path projectDir) throws IOException {
        Map<String, Integer> imports = new TreeMap<>();
        Set<String> configKeys = new TreeSet<>();
        int javaFiles = 0;

        List<Path> files;
        try (Stream<Path> walk = Files.walk(projectDir)) {
            files = walk.filter(Files::isRegularFile).filter(path -> !isSkipped(projectDir.relativize(path))).toList();
        }
        for (Path file : files) {
            String name = file.getFileName().toString();
            if (Files.size(file) > MAX_FILE_BYTES) {
                continue;
            }
            if (name.endsWith(".java")) {
                javaFiles++;
                // 한 파일에 같은 import가 두 번 있어도 파일 수는 한 번으로 센다.
                for (String target : parseImports(Files.readString(file, StandardCharsets.UTF_8))) {
                    imports.merge(target, 1, Integer::sum);
                }
            } else if (isConfigFile(name)) {
                configKeys.addAll(parseConfigKeys(name, Files.readString(file, StandardCharsets.UTF_8)));
            }
        }
        return new SourceUsage(imports, configKeys, javaFiles);
    }

    private static boolean isSkipped(Path relative) {
        for (Path part : relative) {
            if (SKIP_DIRS.contains(part.toString())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isConfigFile(String name) {
        return name.startsWith("application") && (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml"));
    }

    /**
     * 한 파일의 import 대상(중복 없음). static import는 멤버를 떼고 클래스만 남긴다 — breaking change는 대개 클래스 단위로
     * 적히고, "그 클래스를 쓰는가"가 대조의 기준이기 때문이다. 와일드카드는 "패키지.*" 그대로 둔다.
     */
    static Set<String> parseImports(String source) {
        Set<String> targets = new TreeSet<>();
        Matcher matcher = IMPORT.matcher(source);
        while (matcher.find()) {
            boolean isStatic = matcher.group(1) != null;
            String name = matcher.group(2);
            boolean wildcard = matcher.group(3) != null;
            if (wildcard) {
                targets.add(name + ".*"); // static 와일드카드(import static a.B.*)는 클래스 B 전체라 "a.B.*"로 둬도 같은 뜻이다
            } else if (isStatic && name.contains(".")) {
                targets.add(name.substring(0, name.lastIndexOf('.')));
            } else {
                targets.add(name);
            }
        }
        return targets;
    }

    /** 설정 키만 뽑는다(값은 버린다). YAML은 중첩 키를 "a.b.c"로 펼친다. 형식이 깨진 파일은 그 파일만 건너뛴다. */
    static Set<String> parseConfigKeys(String fileName, String content) {
        Set<String> keys = new TreeSet<>();
        try {
            if (fileName.endsWith(".properties")) {
                Properties properties = new Properties();
                properties.load(new StringReader(content));
                properties.stringPropertyNames().forEach(keys::add);
            } else {
                // SafeConstructor: 임의 클래스를 만들지 않는 안전한 로더. 스캔 대상 저장소의 파일이라 신뢰할 수 없다.
                Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
                for (Object document : yaml.loadAll(content)) {
                    flatten("", document, keys);
                }
            }
        } catch (Exception e) {
            log.debug("설정 파일 {}의 키를 읽지 못해 건너뜁니다: {}", fileName, e.toString());
        }
        return keys;
    }

    private static void flatten(String prefix, Object node, Set<String> keys) {
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = prefix.isEmpty() ? String.valueOf(entry.getKey()) : prefix + "." + entry.getKey();
                if (entry.getValue() instanceof Map<?, ?>) {
                    flatten(key, entry.getValue(), keys);
                } else {
                    keys.add(key);
                }
            }
        }
    }
}
