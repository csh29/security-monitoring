package com.sjinc.securitymonitor.service.git;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jgit.api.CloneCommand;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 스캔 대상 프로젝트의 git 저장소를 임시 디렉터리에 clone한다.
 * 의존성 목록만 필요하므로 shallow clone(depth=1)으로 히스토리는 받지 않는다.
 * 인증 정보는 저장소 주소별로 여기서 고른다(GitCredentialResolver) — 스캔 서비스들이 토큰을 들고 다니지 않게.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GitCloneService {

    private final GitCredentialResolver credentialResolver;

    /**
     * @param repoUrl https://github.com/{org}/{repo}.git 형태
     * @param branch  스캔할 브랜치 (main, develop 등)
     * @return        clone된 로컬 디렉터리 (사용 후 반드시 cleanup 호출)
     */
    public File cloneRepository(String repoUrl, String branch) throws IOException {
        Path targetDir = Files.createTempDirectory("cve-scan-");

        CloneCommand clone = Git.cloneRepository()
                .setURI(repoUrl)
                .setBranch(branch)
                .setDirectory(targetDir.toFile())
                .setDepth(1)
                .setCloneSubmodules(false);
        // 일치하는 인증 정보가 없으면 인증 없이 clone한다(공개 저장소). 실패하면 아래 로그로 어느 인증을 썼는지 본다.
        GitCredentialResolver.Credential credential = credentialResolver.resolve(repoUrl).orElse(null);
        if (credential != null) {
            clone.setCredentialsProvider(new UsernamePasswordCredentialsProvider(credential.username(), credential.token()));
        }
        log.info("git clone {} ({}) — 인증: {}", repoUrl, branch, credential == null ? "없음" : credential.source());

        try (Git git = clone.call()) {
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