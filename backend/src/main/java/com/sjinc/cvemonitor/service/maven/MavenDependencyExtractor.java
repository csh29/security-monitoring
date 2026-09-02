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

    public List<MavenDependency> extract(File projectDir) throws Exception {
        Path outputFile = Files.createTempFile("dependency-list-", ".txt");
        try {
            InvocationRequest request = new DefaultInvocationRequest();
            request.setPomFile(new File(projectDir, "pom.xml"));
            request.setGoals(List.of("dependency:list"));
            request.setProperties(outputProperties(outputFile));
            request.setBatchMode(true); // 인터랙티브 프롬프트 방지

            Invoker invoker = new DefaultInvoker();
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
        props.setProperty("includeScope", "compile,runtime"); // test 스코프 제외 (필요시 조정)
        return props;
    }

    private List<MavenDependency> parse(List<String> lines) {
        List<MavenDependency> dependencies = new ArrayList<>();
        for (String rawLine : lines) {
            String line = rawLine.trim();
            Matcher matcher = GAV_PATTERN.matcher(line);
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
}