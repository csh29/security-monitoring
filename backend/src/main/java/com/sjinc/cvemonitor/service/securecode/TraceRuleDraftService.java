package com.sjinc.cvemonitor.service.securecode;

import com.sjinc.cvemonitor.domain.App;
import com.sjinc.cvemonitor.dto.securecode.TraceRuleDraftView;
import com.sjinc.cvemonitor.repository.AppRepository;
import com.sjinc.cvemonitor.service.git.GitCloneService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 코드 점검 화면의 "추적 규칙 초안" 버튼. 등록된 앱의 저장소를 받아 trace-rules.yml 초안을 만들고, 지금 설정과 비교하고,
 * 반영하면 ${} 판정이 어떻게 바뀌는지 미리 돌려 본다.
 *
 * <p>결정론이고 소스는 서버 밖으로 나가지 않는다(AI 없음). 설정 파일은 쓰지 않는다 — 사람이 근거를 확인하고 반영·커밋한다
 * (Semgrep 규칙 폴더와 같은 관리 방식. 서버에 설정 파일 쓰기 경로를 만들지 않기 위함이기도 하다).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TraceRuleDraftService {

    private final AppRepository appRepository;
    private final GitCloneService gitCloneService;

    @Value("${git.access.token}")
    private String gitAccessToken;

    @Value("${git.user.name}")
    private String gitUserName;

    @Value("${securecode.trace-rules:../securecode/trace-rules.yml}")
    private String traceRulesFile;

    /** appId로만 받는다 — 점검과 같이 앱 관리에 등록된 저장소만(임의 URL clone은 토큰 유출·SSRF 위험). */
    public TraceRuleDraftView draft(Long appId) throws Exception {
        App app = appRepository.findById(appId)
                .orElseThrow(() -> new IllegalArgumentException("앱 관리에 등록되지 않은 앱입니다: appId=" + appId));
        TraceRules current = TraceRules.load(Path.of(traceRulesFile));

        File projectDir = gitCloneService.cloneRepository(app.getRepoUrl(), app.getBranch(), gitUserName, gitAccessToken);
        try {
            Map<String, String> sources = MybatisDollarTracer.readSources(projectDir.toPath());
            TraceRuleDrafter.Draft draft = TraceRuleDrafter.draft(sources);
            TraceRules merged = TraceRuleDraftPreview.merge(current, draft, app.getSystemName());
            List<TraceRuleDraftPreview.Change> changes = TraceRuleDraftPreview.changes(
                    MybatisDollarTracer.trace(sources, current), MybatisDollarTracer.trace(sources, merged));

            log.info("[{}] 추적 규칙 초안: 세션 덮어쓰기 후보 {}개, 반영 시 판정 변화 {}건",
                    app.getSystemName(), draft.overwrites().size(), changes.size());
            return toView(app.getSystemName(), draft, TraceRuleDraftPreview.compare(current, draft), changes);
        } finally {
            gitCloneService.cleanup(projectDir);
        }
    }

    static TraceRuleDraftView toView(String systemName, TraceRuleDrafter.Draft draft,
                                     List<TraceRuleDraftPreview.Item> items, List<TraceRuleDraftPreview.Change> changes) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        changes.forEach(c -> counts.merge(c.before().label() + " → " + c.after().label(), 1, Integer::sum));
        return new TraceRuleDraftView(
                systemName,
                TraceRuleDrafter.toYaml(draft, systemName),
                items.stream().map(i -> new TraceRuleDraftView.Item(i.kind(), i.value(), i.status().name(),
                        i.status().label(), i.detail(), i.evidence())).toList(),
                changes.stream().map(c -> new TraceRuleDraftView.Change(c.path() + ":" + c.line(), c.expr(),
                        c.before().label(), c.after().label())).toList(),
                counts.entrySet().stream().map(e -> e.getKey() + " " + e.getValue() + "건").toList(),
                draft.notes(),
                draft.failedFiles().size());
    }
}
