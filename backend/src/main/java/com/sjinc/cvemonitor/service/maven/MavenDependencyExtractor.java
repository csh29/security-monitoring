package com.sjinc.cvemonitor.service.maven;

import com.sjinc.cvemonitor.domain.MavenDependency;
import org.apache.maven.shared.invoker.*;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 대상 프로젝트의 pom.xml을 기준으로 mvn dependency:list를 실행하고,
 * 실제로 해석된(버전 확정, transitive 포함) 의존성 목록을 파싱한다.
 */
@Component
public class MavenDependencyExtractor {

    // groupId:artifactId:packaging[:classifier]:version:scope
    private static final Pattern GAV_PATTERN =
            Pattern.compile("^([\\w.\\-]+):([\\w.\\-]+):([\\w.\\-]+):(?:([\\w.\\-]+):)?([\\w.\\-]+):(\\w+)$");

    public List<MavenDependency> extract(File projectDir, String mavenHome) throws Exception {
        Path outputFile = Files.createTempFile("dependency-list-", ".txt");
        try {
            InvocationRequest request = new DefaultInvocationRequest();
            request.setPomFile(new File(projectDir, "pom.xml"));
            request.setGoals(List.of("dependency:list"));
            request.setProperties(outputProperties(outputFile));
            request.setBatchMode(true); // 인터랙티브 프롬프트 방지

            Invoker invoker = new DefaultInvoker();
            invoker.setMavenHome(new File(mavenHome));
            InvocationResult result = invoker.execute(request);

            if (result.getExitCode() != 0) {
                throw new IllegalStateException(
                        "mvn dependency:list 실행 실패: " + projectDir, result.getExecutionException());
            }

            return parse(Files.readAllLines(outputFile));
        } finally {
            Files.deleteIfExists(outputFile);
        }
    }

    private Properties outputProperties(Path outputFile) {
        Properties props = new Properties();
        props.setProperty("outputFile", outputFile.toAbsolutePath().toString());
        props.setProperty("outputAbsoluteArtifactFilename", "false");
        props.setProperty("includeScope", "runtime"); // compile,runtime → runtime 하나로 수정 (runtime이 compile을 포함함)
        return props;
    }

    private List<MavenDependency> parse(List<String> lines) {
        List<MavenDependency> dependencies = new ArrayList<>();
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty()) continue;

            // 줄 끝의 "(optional)", "-- module xxx [auto]" 같은 JPMS 모듈 정보는 무시하고
            // 맨 앞 GAV:scope 토큰만 취한다.
            String gavToken = line.split("\\s+", 2)[0];

            Matcher matcher = GAV_PATTERN.matcher(gavToken);
            if (matcher.matches()) {
                dependencies.add(new MavenDependency(
                        matcher.group(1),  // groupId
                        matcher.group(2),  // artifactId
                        matcher.group(5)   // version
                ));
            }
        }
        return dependencies;
    }

    /**
     * dependency:tree를 프로젝트당 딱 한 번만 실행해서, "groupId:artifactId" → 이를 끌고 들어온
     * 최상위(depth 1) 직접 의존성의 "groupId:artifactId" 매핑과, fix-plan 배치가 참고할 원문 텍스트를 함께 반환한다.
     * CVE 건수만큼 매번 mvn 프로세스를 새로 띄우지 않도록 한 번만 실행한다.
     * 직접 의존성 자신은 스스로를 가리킨다. 실패하면 빈 결과를 반환한다(스캔 자체를 실패시키지 않음).
     */
    public DependencyTreeResult buildTopLevelCauseMap(File projectDir, String mavenHome) {
        Path outputFile = null;
        try {
            outputFile = Files.createTempFile("dependency-tree-full-", ".txt");

            InvocationRequest request = new DefaultInvocationRequest();
            request.setPomFile(new File(projectDir, "pom.xml"));
            request.setGoals(List.of("dependency:tree"));

            Properties props = new Properties();
            props.setProperty("outputFile", outputFile.toAbsolutePath().toString());
            request.setProperties(props);
            request.setBatchMode(true);

            Invoker invoker = new DefaultInvoker();
            invoker.setMavenHome(new File(mavenHome));
            InvocationResult result = invoker.execute(request);

            if (result.getExitCode() != 0) {
                return new DependencyTreeResult(Map.of(), "");
            }

            List<String> lines = Files.readAllLines(outputFile);
            return new DependencyTreeResult(parseTopLevelCauseMap(lines), String.join("\n", lines));
        } catch (Exception e) {
            return new DependencyTreeResult(Map.of(), "");
        } finally {
            if (outputFile != null) {
                try {
                    Files.deleteIfExists(outputFile);
                } catch (Exception ignored) {
                    // 임시 파일 정리 실패는 무시한다.
                }
            }
        }
    }

    public record DependencyTreeResult(Map<String, String> topLevelCauseByCoordinate, String rawText) {}

    /**
     * dependency:tree 텍스트 전체를 한 줄씩 훑으면서, depth 1(직접 의존성) 줄을 만날 때마다
     * "현재 최상위 원인"을 갱신하고, 그 아래로 이어지는 depth 2 이상의 모든 줄에 그 원인을 매핑한다.
     * (텍스트가 위→아래 DFS 순서라 별도 스택 없이 "마지막으로 본 depth 1"만 기억하면 된다.)
     */
    private Map<String, String> parseTopLevelCauseMap(List<String> lines) {
        Map<String, String> causeByCoordinate = new HashMap<>();
        String currentTopLevel = null;

        for (int i = 1; i < lines.size(); i++) { // 0번째 줄은 루트 프로젝트 자신이라 건너뛴다.
            ParsedTreeLine parsed = parseTreeLine(lines.get(i));
            if (parsed == null) continue;

            if (parsed.depth() == 1) {
                currentTopLevel = parsed.coordinate();
                causeByCoordinate.put(parsed.coordinate(), parsed.coordinate());
            } else if (currentTopLevel != null) {
                causeByCoordinate.put(parsed.coordinate(), currentTopLevel);
            }
        }
        return causeByCoordinate;
    }

    /**
     * dependency:tree 원문에서 targetCoordinates(groupId:artifactId) 각각의 "최상위 직접 의존성부터
     * 자기 자신까지" 조상 체인을 구해서 돌려준다. fix-plan reasoning의 "경로:" 줄은 이 값을 그대로
     * 인용하기만 하면 된다 — AI가 dependency:tree 텍스트를 눈으로 다시 훑어 경로를 재구성하다가
     * 이름이 비슷한 형제 노드(예: spring-security-config vs spring-security-web)를 혼동하는 실수를
     * 구조적으로 없애기 위한 용도다. 체인 크기가 1이면(자기 자신뿐) 최상위 직접 의존성이라는 뜻이다.
     */
    public Map<String, List<String>> resolveChains(String rawText, Set<String> targetCoordinates) {
        Map<String, List<String>> result = new HashMap<>();
        if (rawText == null || rawText.isBlank() || targetCoordinates.isEmpty()) return result;

        List<String> lines = rawText.lines().toList();
        List<String> ancestors = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            ParsedTreeLine parsed = parseTreeLine(lines.get(i));
            if (parsed == null) continue;

            while (ancestors.size() >= parsed.depth()) {
                ancestors.remove(ancestors.size() - 1);
            }
            ancestors.add(parsed.coordinate());

            if (targetCoordinates.contains(parsed.coordinate()) && !result.containsKey(parsed.coordinate())) {
                result.put(parsed.coordinate(), List.copyOf(ancestors));
            }
        }
        return result;
    }

    /**
     * dependency:tree 원문에서 targetCoordinates(groupId:artifactId)로 가는 경로에 해당하는 줄만 남긴다.
     * fix-plan 프롬프트에 CVE와 무관한 나머지 서브트리(수십~수백 줄)까지 통째로 넣지 않기 위한 용도라,
     * 토큰 절감이 목적이지 정확한 트리 재현이 목적이 아니다 — 매칭되는 게 없으면 원문을 그대로 반환한다.
     */
    public String pruneToPaths(String rawText, Set<String> targetCoordinates) {
        if (rawText == null || rawText.isBlank() || targetCoordinates.isEmpty()) return rawText;

        List<String> lines = rawText.lines().toList();
        if (lines.isEmpty()) return rawText;

        TreeSet<Integer> keepIndices = new TreeSet<>();
        keepIndices.add(0); // 0번째 줄은 루트 프로젝트 자신이라 항상 포함한다.

        List<Integer> ancestorIndices = new ArrayList<>(); // depth 순서로 쌓인 현재 조상 줄의 인덱스
        for (int i = 1; i < lines.size(); i++) {
            ParsedTreeLine parsed = parseTreeLine(lines.get(i));
            if (parsed == null) continue;

            while (ancestorIndices.size() >= parsed.depth()) {
                ancestorIndices.remove(ancestorIndices.size() - 1);
            }
            ancestorIndices.add(i);

            if (targetCoordinates.contains(parsed.coordinate())) {
                keepIndices.addAll(ancestorIndices);
            }
        }

        if (keepIndices.size() <= 1) return rawText; // 하나도 못 찾았으면 원문을 그대로 넘긴다(안전망).
        return keepIndices.stream().map(lines::get).collect(Collectors.joining("\n"));
    }

    /** "|  " 또는 "   " 3글자 단위 들여쓰기 뒤에 오는 "+- "/"\- " 마커를 걷어내고 depth와 좌표를 뽑는다. */
    private ParsedTreeLine parseTreeLine(String line) {
        int i = 0;
        int depth = 0;
        while (i + 3 <= line.length() && (line.startsWith("|  ", i) || line.startsWith("   ", i))) {
            i += 3;
            depth++;
        }
        if (!(line.startsWith("+- ", i) || line.startsWith("\\- ", i))) {
            return null;
        }
        depth += 1;

        String[] parts = line.substring(i + 3).split(":");
        if (parts.length < 2) return null;

        return new ParsedTreeLine(depth, parts[0] + ":" + parts[1]);
    }

    private record ParsedTreeLine(int depth, String coordinate) {}
}