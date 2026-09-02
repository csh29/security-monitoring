package com.sjinc.cvemonitor.service.git;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 스캔 대상 프로젝트의 git 저장소를 임시 디렉터리에 clone한다.
 * 의존성 목록만 필요하므로 shallow clone(depth=1)으로 히스토리는 받지 않는다.
 */
@Component
public class GitCloneService {

    /**
     * @param repoUrl https://github.com/{org}/{repo}.git 형태
     * @param branch  스캔할 브랜치 (main, develop 등)
     * @param token   PAT(Personal Access Token) 또는 GitHub App installation token
     * @return        clone된 로컬 디렉터리 (사용 후 반드시 cleanup 호출)
     */
    public File cloneRepository(String repoUrl, String branch, String gitUserName, String token) throws IOException {
        Path targetDir = Files.createTempDirectory("cve-scan-");

        // GitHub HTTPS 인증 방식: PAT를 username 자리에, password는 빈 문자열로
        CredentialsProvider credentials = new UsernamePasswordCredentialsProvider(gitUserName, token);

        try (Git git = Git.cloneRepository()
                .setURI(repoUrl)
                .setBranch(branch)
                .setDirectory(targetDir.toFile())
                .setCredentialsProvider(credentials)
                .setDepth(1)
                .setCloneSubmodules(false)
                .call()) {
            return targetDir.toFile();
        } catch (Exception e) {
            deleteRecursively(targetDir.toFile());
            throw new IOException("git clone 실패: " + repoUrl, e);
        }
    }

    /** 스캔 완료 후 반드시 호출해서 임시 디렉터리를 정리한다 (안 지우면 디스크가 계속 쌓임). */
    public void cleanup(File directory) {
        deleteRecursively(directory);
    }

    private void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        file.delete();
    }
}