package com.sjinc.cvemonitor.service.app;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.dto.app.AppRequest;
import com.sjinc.cvemonitor.repository.AppRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** 앱 관리 화면(조회/저장/삭제 버튼)의 처리를 담당한다. */
@Service
@RequiredArgsConstructor
public class AppService {

    private final AppRepository appRepository;

    @Transactional(readOnly = true)
    public List<App> getAllApps() {
        return appRepository.findAllByOrderByIdAsc();
    }

    /** request.id()가 있으면 수정, 없으면 신규 등록. */
    @Transactional
    public App saveApp(AppRequest request) {
        App app = App.builder()
                .id(request.id())
                .repoUrl(request.repoUrl())
                .branch(request.branch())
                .systemName(request.systemName())
                .description(request.description())
                .build();
        return appRepository.save(app);
    }

    @Transactional
    public void deleteApp(Long id) {
        appRepository.deleteById(id);
    }
}
