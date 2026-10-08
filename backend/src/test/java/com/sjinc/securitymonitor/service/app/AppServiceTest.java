package com.sjinc.securitymonitor.service.app;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.dto.app.AppRequest;
import com.sjinc.securitymonitor.repository.AppRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AppServiceTest {

    private AppService service;

    @BeforeEach
    void setUp() {
        AppRepository repository = mock(AppRepository.class);
        when(repository.save(any(App.class))).thenAnswer(inv -> inv.getArgument(0));
        service = new AppService(repository, new RepoUrlValidator(List.of("git.sejung.co.kr")));
    }

    private static AppRequest request(String sourceType, String repoUrl, String branch) {
        return new AppRequest(null, repoUrl, branch, "LEGACY", "옛 시스템", null, null, sourceType);
    }

    @Test
    void 소스_업로드_앱은_저장소_없이_저장되고_남은_저장소_값은_지운다() {
        App saved = service.saveApp(request(App.SOURCE_UPLOAD, "https://evil.example.com/x.git", "main"));

        // 업로드 앱에 옛 URL이 남으면 라이브러리 스캔이 그 주소로 clone할 수 있다 — 저장소 검증도 하지 않고 값을 버린다
        assertThat(saved.isUploadSource()).isTrue();
        assertThat(saved.getRepoUrl()).isNull();
        assertThat(saved.getBranch()).isNull();
    }

    @Test
    void Git_앱은_저장소_검증과_브랜치가_필요하고_출처가_비면_Git이다() {
        App saved = service.saveApp(request(null, "https://git.sejung.co.kr/crm/a.git", "dev"));
        assertThat(saved.getSourceType()).isEqualTo(App.SOURCE_GIT);

        assertThatThrownBy(() -> service.saveApp(request(App.SOURCE_GIT, "https://git.sejung.co.kr/crm/a.git", " ")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Branch");
        assertThatThrownBy(() -> service.saveApp(request(App.SOURCE_GIT, "https://evil.example.com/a.git", "dev")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 모르는_소스_출처는_거부한다() {
        assertThatThrownBy(() -> service.saveApp(request("FTP", null, null)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("소스 출처");
    }
}
