package com.sjinc.securitymonitor.service.securecode;

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
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * 규칙 폴더(securecode/rules)의 규칙 id 목록과 규칙셋 버전을 읽는다. Semgrep 결과 JSON에는 "어떤 규칙을 돌렸는지"가 없어서
 * 직접 읽는다.
 *
 * <p>규칙 id 목록은 재점검 비교에 쓴다 — 규칙 파일에서 지운 규칙의 기존 탐지가 "이번에 안 걸림 = 조치완료"로 집계되면 안 된다.
 */
public class RuleSetLoader {

    public record RuleSet(Set<String> ruleIds, String version) {
    }

    public RuleSet load(Path rulesDir) throws IOException {
        return load(rulesDir, List.of());
    }

    /**
     * @param extraFiles 규칙셋 버전 해시에 함께 넣을 파일(있을 때만). 연계 추적 규칙(trace-rules.yml)이 바뀌면 같은 코드도 판정이
     *                   달라지므로, 점검 이력의 규칙셋 버전으로 "판정이 왜 바뀌었는지"를 추적할 수 있게 넣는다.
     */
    public RuleSet load(Path rulesDir, List<Path> extraFiles) throws IOException {
        if (!Files.isDirectory(rulesDir)) {
            throw new SecureCodeScanException("규칙 폴더가 없습니다. 서버 설정 securecode.rules-dir을 확인하세요.", null);
        }
        List<Path> files;
        try (Stream<Path> walk = Files.walk(rulesDir)) {
            // 순서가 매번 같아야 버전 해시가 같다.
            files = walk.filter(Files::isRegularFile).filter(RuleSetLoader::isRuleFile).sorted().toList();
        }

        Set<String> ruleIds = new TreeSet<>();
        MessageDigest digest = sha256();
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        for (Path file : files) {
            byte[] bytes = Files.readAllBytes(file);
            digest.update(bytes);
            ruleIds.addAll(ruleIds(yaml.load(new String(bytes, StandardCharsets.UTF_8))));
        }
        for (Path extra : extraFiles) {
            if (Files.isRegularFile(extra)) digest.update(Files.readAllBytes(extra));
        }
        // 규칙이 하나도 없으면 "약점 0건"으로 점검이 성공해 기존 탐지가 전부 해결 처리된다 — 점검을 실패시킨다.
        if (ruleIds.isEmpty()) {
            throw new SecureCodeScanException("규칙 폴더에 규칙이 없습니다. 서버 설정 securecode.rules-dir을 확인하세요.", null);
        }
        return new RuleSet(ruleIds, HexFormat.of().formatHex(digest.digest()).substring(0, 12));
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
