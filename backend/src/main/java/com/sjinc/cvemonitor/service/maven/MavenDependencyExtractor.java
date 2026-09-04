package com.sjinc.cvemonitor.service.maven;

import com.sjinc.cvemonitor.domain.MavenDependency;
import org.apache.maven.shared.invoker.*;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
}