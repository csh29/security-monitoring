package com.sjinc.securitymonitor.service.securecode.semgrep;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;
import com.sjinc.securitymonitor.exception.SecureCodeScanException;
import com.sjinc.securitymonitor.service.securecode.trace.TraceSink;

/**
 * 규칙 폴더의 규칙 id 목록·규칙셋 버전·연계 추적 대상(metadata.trace)을 읽는다(Semgrep 결과에는 돌린 규칙이 없다).
 * 규칙 id 목록은 지운 규칙의 탐지가 재점검에서 조치완료로 집계되지 않게 하는 데 쓴다.
 */
public class RuleSetLoader {

    /** @param sinks 연계 추적을 받는 규칙 id → 따라갈 값(metadata.trace가 있는 규칙만) */
    public record RuleSet(Set<String> ruleIds, String version, Map<String, TraceSink> sinks) {
    }

    public RuleSet load(Path rulesDir) throws IOException {
        return load(rulesDir, List.of());
    }

    /**
     * @param extraContents 버전 해시에 함께 넣을 내용(판정이 바뀐 이유를 이력에서 찾게 추적 규칙의 판정 부분을 넣는다)
     */
    public RuleSet load(Path rulesDir, List<String> extraContents) throws IOException {
        if (!Files.isDirectory(rulesDir)) {
            throw new SecureCodeScanException("규칙 폴더가 없습니다. 서버 설정 securecode.rules-dir을 확인하세요.", null);
        }
        List<Path> files;
        try (Stream<Path> walk = Files.walk(rulesDir)) {
            // 순서가 매번 같아야 버전 해시가 같다.
            files = walk.filter(Files::isRegularFile).filter(RuleSetLoader::isRuleFile).sorted().toList();
        }

        Set<String> ruleIds = new TreeSet<>();
        Map<String, TraceSink> sinks = new TreeMap<>();
        MessageDigest digest = sha256();
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        for (Path file : files) {
            byte[] bytes = Files.readAllBytes(file);
            digest.update(bytes);
            Object document = yaml.load(new String(bytes, StandardCharsets.UTF_8));
            ruleIds.addAll(ruleIds(document));
            try {
                sinks.putAll(sinks(document));
            } catch (IllegalArgumentException e) {
                throw new SecureCodeScanException(e.getMessage() + " — 규칙 파일 " + file.getFileName(), e);
            }
        }
        for (String extra : extraContents) {
            if (!extra.isEmpty()) digest.update(extra.getBytes(StandardCharsets.UTF_8));
        }
        // 규칙이 하나도 없으면 "약점 0건"으로 점검이 성공해 기존 탐지가 전부 해결 처리된다 — 점검을 실패시킨다.
        if (ruleIds.isEmpty()) {
            throw new SecureCodeScanException("규칙 폴더에 규칙이 없습니다. 서버 설정 securecode.rules-dir을 확인하세요.", null);
        }
        return new RuleSet(ruleIds, HexFormat.of().formatHex(digest.digest()).substring(0, 12), sinks);
    }

    static Map<String, TraceSink> sinks(Object document) {
        Map<String, TraceSink> sinks = new TreeMap<>();
        if (document instanceof Map<?, ?> map && map.get("rules") instanceof List<?> rules) {
            for (Object rule : rules) {
                if (rule instanceof Map<?, ?> ruleMap && ruleMap.get("id") != null) {
                    String id = String.valueOf(ruleMap.get("id"));
                    TraceSink sink = TraceSink.fromMetadata(id, ruleMap.get("metadata"));
                    if (sink != null) sinks.put(id, sink);
                }
            }
        }
        return sinks;
    }

    static Set<String> ruleIds(Object document) {
        Set<String> ids = new TreeSet<>();
        if (document instanceof Map<?, ?> map && map.get("rules") instanceof List<?> rules) {
            for (Object rule : rules) {
                if (rule instanceof Map<?, ?> ruleMap && ruleMap.get("id") != null) {
                    ids.add(String.valueOf(ruleMap.get("id")));
                }
            }
        }
        return ids;
    }

    private static boolean isRuleFile(Path path) {
        String name = path.getFileName().toString();
        return name.endsWith(".yml") || name.endsWith(".yaml");
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
