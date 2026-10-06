package com.sjinc.securitymonitor.service.app;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.dto.app.AppRequest;
import com.sjinc.securitymonitor.repository.AppRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.regex.Pattern;

/** 앱 관리 화면(조회/저장/삭제 버튼)의 처리를 담당한다. */
@Service
@RequiredArgsConstructor
public class AppService {

    private final AppRepository appRepository;
    private final RepoUrlValidator repoUrlValidator;

    /** 오타(골뱅이·도메인 누락) 정도만 거르는 느슨한 형식 검사. 실제 수신 가능 여부는 발송해 봐야 안다. */
    private static final Pattern EMAIL = Pattern.compile("[^@\\s]+@[^@\\s]+\\.[^@\\s]+");

    @Transactional(readOnly = true)
    public List<App> getAllApps() {
        return appRepository.findAllByOrderByIdAsc();
    }

    /** request.id()가 있으면 수정, 없으면 신규 등록. */
    @Transactional
    public App saveApp(AppRequest request) {
        // 여기 등록된 URL은 나중에 스캔이 PAT를 들고 clone하고, 받아온 pom.xml로 Maven을 돌리는
        // 대상이 된다 — 저장 시점에 거르지 않으면 그 뒤로는 거를 자리가 없다.
        repoUrlValidator.validate(request.repoUrl());
        String managerEmail = blankToNull(request.managerEmail());
        // 알림 메일 수신처로 쓸 값이라, 형식이 틀린 채 저장되면 발송 시점에야(SES 거절로) 드러난다.
        if (managerEmail != null && !EMAIL.matcher(managerEmail).matches()) {
            throw new IllegalArgumentException("담당자 이메일 형식이 올바르지 않습니다: " + managerEmail);
        }

        App app = App.builder()
                .id(request.id())
                .repoUrl(request.repoUrl())
                .branch(request.branch())
                .systemName(request.systemName())
                .description(request.description())
                .managerName(blankToNull(request.managerName()))
                .managerEmail(managerEmail)
                .build();
        return appRepository.save(app);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    @Transactional
    public void deleteApp(Long id) {
        appRepository.deleteById(id);
    }
}
