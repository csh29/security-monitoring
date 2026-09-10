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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        } catch(Exception e ) {
            System.out.println(e);
        }finally {
            Files.deleteIfExists(outputFile);
        }
        return null;
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
                        matcher.group(5),  // version
                        matcher.group(6)   // scope
                ));
            }
        }
        return dependencies;
    }

    public String findDependencyPath(File projectDir, String groupId, String artifactId, String mavenHome) throws Exception {
        Path outputFile = Files.createTempFile("dependency-tree-", ".txt");
        try {
            InvocationRequest request = new DefaultInvocationRequest();
            request.setPomFile(new File(projectDir, "pom.xml"));
            request.setGoals(List.of("dependency:tree"));

            Properties props = new Properties();
            props.setProperty("outputFile", outputFile.toAbsolutePath().toString());
            props.setProperty("includes", groupId + ":" + artifactId); // 이 의존성만 필터링
            request.setProperties(props);
            request.setBatchMode(true);

            Invoker invoker = new DefaultInvoker();
            invoker.setMavenHome(new File(mavenHome));
            InvocationResult result = invoker.execute(request);

            if (result.getExitCode() != 0) {
                throw new IllegalStateException("dependency:tree 실행 실패: " + projectDir);
            }
            return Files.readString(outputFile);
        } finally {
            Files.deleteIfExists(outputFile);
        }
    }

    /**
     * dependency:tree를 프로젝트당 딱 한 번만 실행해서, "groupId:artifactId" → 이를 끌고 들어온
     * 최상위(depth 1) 직접 의존성의 "groupId:artifactId" 매핑과, fix-plan 배치가 참고할 원문 텍스트를 함께 반환한다.
     * CVE 건수만큼 매번 mvn 프로세스를 새로 띄우던 것(findDependencyPath 반복 호출)을 대체한다.
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