package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.TraceRuleProposal;
import com.sjinc.securitymonitor.dto.securecode.TraceRuleProposalView;
import com.sjinc.securitymonitor.repository.TraceRuleProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex;

/**
 * 추적 규칙(trace-rules.yml)을 읽고, 코드 점검 때 만든 초안을 반영한다.
 *
 * <p>점검마다(연계 추적 단계) 그 저장소의 프레임워크 장치·설정 파일을 읽어 초안을 만들고(TraceRuleDrafter) 지금 규칙과 비교해
 * (TraceRuleChangePlanner):
 * <ul>
 *   <li>판정을 엄격하게 하거나 판정에 쓰지 않는 변경은 <b>바로 파일에 반영</b>하고 그 점검부터 쓴다(AUTO_APPLIED로 기록).</li>
 *   <li>판정을 느슨하게 하는 변경은 <b>확인 대기</b>(PENDING)로 저장한다. 사람이 코드 점검 화면에서 근거를 보고 반영하면 그때 파일에 쓰고
 *       다음 점검부터 쓴다. 잘못 반영하면 진짜 취약점이 조용히 LOW가 되기 때문이다(CRM regPgmId 사례).</li>
 * </ul>
 * 파일은 바꿀 줄만 고치고 주석을 남긴다(TraceRulesFileEditor) — 서버가 고친 내용도 사람이 git으로 확인·커밋한다.
 * 점검(점검 잠금 안)과 화면의 반영이 동시에 파일을 쓰지 않게 파일 쓰기는 한 번에 하나만 한다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TraceRuleService {

    static final int MAX_ROWS = 500;

    private final TraceRuleProposalRepository proposalRepository;
    private final ObjectMapper objectMapper;

    /** 규칙 폴더 밖에 둔다 — 안에 두면 Semgrep이 규칙으로 읽는다. */
    @Value("${securecode.trace-rules:../securecode/trace-rules.yml}")
    private String traceRulesFile;

    private final Object fileLock = new Object();

    /**
     * 점검 한 번의 규칙 확인 결과.
     *
     * @param rules        파일의 규칙 전체(바로 반영한 변경까지 들어간 것) — 추적에는 이 시스템 기준으로 합친 effective()를 쓴다
     * @param system       점검한 앱의 시스템명
     * @param pending      확인 대기 중인 이 저장소의 변경(사람이 무시한 것은 빼고)
     * @param note         점검 완료 알림에 붙일 문구(없으면 null). 대기 변경의 판정 영향 수는 추적 뒤에 붙인다(pendingNote)
     * @param rulesChanged 이번 점검에서 파일을 고쳤는가 — 고쳤으면 규칙셋 버전을 다시 계산한다
     */
    public record Review(TraceRules rules, String system, List<TraceRuleChange> pending, String note, boolean rulesChanged) {

        /** 이번 점검의 연계 추적에 쓸 규칙 — 공통 + 이 시스템 항목. */
        public TraceRules effective() {
            return rules.forSystem(system);
        }

        /** 대기 변경을 모두 반영했다고 친 규칙(이 시스템 기준) — 반영하면 판정이 몇 건 바뀌는지 미리 계산할 때 쓴다. */
        public TraceRules withPending() {
            TraceRules result = rules;
            for (TraceRuleChange change : pending) result = change.applyTo(result);
            return result.forSystem(system);
        }
    }

    public TraceRules load() throws IOException {
        Path file = Path.of(traceRulesFile);
        if (!Files.isRegularFile(file)) {
            log.warn("연계 추적 규칙 파일이 없습니다({}) — 세션 덮어쓰기를 모르므로 해당 ${…}는 클라이언트 값으로 판정됩니다.",
                    file.toAbsolutePath().normalize());
        }
        return TraceRules.load(file);
    }

    /** 규칙셋 버전 해시에 넣을 내용 — 판정에 쓰는 부분만(프레임워크 구조 기록은 뺀다). 파일이 없으면 빈 문자열. */
    public String judgmentContent() throws IOException {
        Path file = Path.of(traceRulesFile);
        return Files.isRegularFile(file) ? TraceRulesFileEditor.judgmentPart(Files.readString(file, StandardCharsets.UTF_8)) : "";
    }

    /**
     * 점검 중 규칙 확인(점검 잠금 안에서 부른다). 초안을 만들고 바로 반영할 변경은 파일에 쓰고, 나머지는 확인 대기로 저장한다.
     * 실패해도 점검은 계속한다 — 지금 규칙을 그대로 쓰고 알림만 남긴다.
     */
    public Review review(App app, Map<String, String> sources, JavaSourceIndex java, TraceRules current) {
        TraceRuleChangePlanner.Plan plan;
        try {
            TraceRuleDrafter.Draft draft = TraceRuleDrafter.draft(sources, java);
            plan = TraceRuleChangePlanner.plan(current, draft, app.getSystemName());
        } catch (Exception e) {
            log.warn("[{}] 추적 규칙 초안을 만들지 못했습니다(지금 규칙으로 계속)", app.getSystemName(), e);
            return new Review(current, app.getSystemName(), List.of(), "추적 규칙 초안을 만들지 못했습니다. 서버 로그를 확인하세요.", false);
        }
        plan.notes().forEach(n -> log.info("[{}] 추적 규칙 확인: {}", app.getSystemName(), n));

        List<String> notes = new ArrayList<>();
        TraceRules rules = current;
        boolean changed = false;
        List<TraceRuleChange> review = new ArrayList<>(plan.needsReview());
        List<TraceRuleChange> automatic = plan.automatic();
        if (!automatic.isEmpty()) {
            try {
                rules = write(automatic, LocalDate.now() + " 자동 반영");
                changed = true;
                automatic.forEach(c -> record(app, c, TraceRuleProposal.AUTO_APPLIED));
                log.info("[{}] 추적 규칙 자동 반영: {}", app.getSystemName(), automatic.stream().map(this::describe).toList());
                List<String> judged = automatic.stream().filter(c -> c.type() != TraceRuleChange.Type.SET_FRAMEWORK)
                        .map(this::describe).toList();
                if (!judged.isEmpty()) notes.add("추적 규칙을 자동으로 고쳤습니다(판정이 더 엄격해짐): " + String.join(", ", judged));
            } catch (Exception e) {
                // 엄격하게 하는 변경을 못 썼으면 사람이 보게 대기로 돌린다 — 조용히 버리면 위험을 놓치는 규칙이 그대로 남는다.
                log.warn("[{}] 추적 규칙 자동 반영 실패 — 확인 대기로 돌립니다", app.getSystemName(), e);
                notes.add("추적 규칙 자동 반영에 실패해 확인 대기로 돌렸습니다: " + e.getMessage());
                review.addAll(automatic.stream().filter(c -> c.type() != TraceRuleChange.Type.SET_FRAMEWORK).toList());
            }
        }
        List<TraceRuleChange> pending = savePending(app, review);
        return new Review(rules, app.getSystemName(), pending, notes.isEmpty() ? null : String.join("\n", notes), changed);
    }

    /** 점검 완료 알림에 붙일 확인 대기 안내. 대기가 없으면 null. */
    public String pendingNote(Review review, int judgmentChanges) {
        if (review.pending().isEmpty()) return null;
        return "추적 규칙 확인 대기 " + review.pending().size() + "건 — "
                + String.join(", ", review.pending().stream().limit(5).map(this::describe).toList())
                + (review.pending().size() > 5 ? " 외" : "")
                + ". 반영하면 판정 " + judgmentChanges + "건이 바뀝니다. 코드 점검 화면의 [추적 규칙 초안]에서 근거를 보고 반영하세요.";
    }

    @Transactional(readOnly = true)
    public List<TraceRuleProposalView> getProposals(String status) {
        return proposalRepository.findLatest(status, PageRequest.of(0, MAX_ROWS)).stream().map(this::toView).toList();
    }

    /**
     * 고른 확인 대기 변경을 파일에 반영한다. 하나라도 파일에 쓰지 못하면 아무것도 반영하지 않는다(파일은 한 번에 쓴다).
     * 다음 점검부터 쓰인다.
     *
     * @return 반영한 건수
     */
    public int apply(List<Long> ids, String user) throws IOException {
        List<TraceRuleProposal> targets = pendingOf(ids);
        if (targets.isEmpty()) return 0;
        List<TraceRuleChange> changes = targets.stream().map(this::changeOf).toList();
        TraceRules before = load();
        try {
            write(changes, LocalDate.now() + " 반영 " + user);
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
        // 파일을 쓴 뒤에 상태를 바꾼다. 그 사이 실패하면 대기로 남지만, 변경은 두 번 적용해도 같아 다시 반영해도 된다.
        for (int i = 0; i < targets.size(); i++) {
            boolean already = changes.get(i).applyTo(before).equals(before);
            targets.get(i).decide(TraceRuleProposal.APPLIED, user, already ? "이미 반영돼 있었음" : null);
        }
        proposalRepository.saveAll(targets);
        log.info("추적 규칙 반영({}): {}", user, changes.stream().map(this::describe).toList());
        return targets.size();
    }

    /** 고른 확인 대기 변경을 무시한다 — 같은 변경은 다시 묻지 않는다. */
    @Transactional
    public int dismiss(List<Long> ids, String user) {
        List<TraceRuleProposal> targets = pendingOf(ids);
        targets.forEach(p -> p.decide(TraceRuleProposal.DISMISSED, user, null));
        log.info("추적 규칙 초안 무시({}): {}", user, targets.stream().map(TraceRuleProposal::getSummary).toList());
        return targets.size();
    }

    // ---------------------------------------------------------------- 파일

    /** 변경을 파일에 쓰고 쓴 뒤의 규칙을 돌려준다. 파일 줄바꿈(CRLF/LF)은 원래대로 둔다. */
    private TraceRules write(List<TraceRuleChange> changes, String stamp) throws IOException {
        synchronized (fileLock) {
            Path file = Path.of(traceRulesFile);
            String content = Files.isRegularFile(file) ? Files.readString(file, StandardCharsets.UTF_8) : "";
            String edited = TraceRulesFileEditor.apply(content, changes, stamp);
            if (content.contains("\r\n")) edited = edited.replace("\n", "\r\n");
            if (!edited.equals(content)) {
                Path dir = file.toAbsolutePath().getParent();
                Files.createDirectories(dir);
                // 임시 파일에 다 쓴 뒤 바꿔 끼운다 — 쓰다 죽어도 반쯤 쓴 규칙 파일이 남지 않게.
                Path temp = Files.createTempFile(dir, "trace-rules", ".tmp");
                try {
                    Files.writeString(temp, edited, StandardCharsets.UTF_8);
                    try {
                        Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                    } catch (AtomicMoveNotSupportedException e) {
                        Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
                    }
                } finally {
                    Files.deleteIfExists(temp);
                }
            }
            return TraceRules.parse(edited);
        }
    }

    // ---------------------------------------------------------------- 확인 대기

    /** 대기 변경을 저장한다. 같은 변경이 대기 중이면 묶고, 무시된 변경은 빼고 돌려준다. 이 앱의 대기 중 이번에 안 나온 것은 OBSOLETE. */
    private List<TraceRuleChange> savePending(App app, List<TraceRuleChange> changes) {
        List<TraceRuleChange> pending = new ArrayList<>();
        Set<String> keys = new HashSet<>();
        try {
            for (TraceRuleChange change : changes) {
                keys.add(change.key());
                TraceRuleProposal latest = proposalRepository.findFirstByChangeKeyOrderByIdDesc(change.key()).orElse(null);
                if (latest != null && TraceRuleProposal.DISMISSED.equals(latest.getStatus())) continue;
                if (latest != null && latest.isPending()) {
                    latest.seenAgain(app.getId(), app.getSystemName(), json(change), describe(change));
                    proposalRepository.save(latest);
                } else {
                    record(app, change, TraceRuleProposal.PENDING);
                }
                pending.add(change);
            }
            for (TraceRuleProposal old : proposalRepository.findByAppIdAndStatus(app.getId(), TraceRuleProposal.PENDING)) {
                if (!keys.contains(old.getChangeKey())) {
                    old.decide(TraceRuleProposal.OBSOLETE, "자동", "다시 점검했을 때 나오지 않음(코드가 바뀌었거나 규칙이 이미 맞음)");
                    proposalRepository.save(old);
                }
            }
        } catch (Exception e) {
            // 대기 저장은 부가 기능 — 실패해도 점검은 계속하고, 알림에는 이번 초안이 그대로 보이게 돌려준다.
            log.warn("[{}] 추적 규칙 확인 대기 저장 실패", app.getSystemName(), e);
            return changes;
        }
        return pending;
    }

    private void record(App app, TraceRuleChange change, String status) {
        proposalRepository.save(TraceRuleProposal.create(app.getId(), app.getSystemName(), change.key(), change.type().name(),
                json(change), describe(change), status));
    }

    private List<TraceRuleProposal> pendingOf(List<Long> ids) {
        if (ids == null || ids.isEmpty()) throw new IllegalArgumentException("반영할 초안을 선택하세요.");
        return proposalRepository.findAllById(ids).stream().filter(TraceRuleProposal::isPending).toList();
    }

    private String describe(TraceRuleChange change) {
        return change.type().label() + " " + change.summary();
    }

    private String json(TraceRuleChange change) {
        try {
            return objectMapper.writeValueAsString(change);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private TraceRuleChange changeOf(TraceRuleProposal proposal) {
        try {
            return objectMapper.readValue(proposal.getChangeJson(), TraceRuleChange.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("추적 규칙 초안을 읽지 못했습니다: id=" + proposal.getId(), e);
        }
    }

    private TraceRuleProposalView toView(TraceRuleProposal p) {
        TraceRuleChange change = changeOf(p);
        return new TraceRuleProposalView(p.getId(), p.getAppId(), p.getSystemName(), p.getStatus(), p.getChangeType(),
                change.type().label(), change.summary(), change.effect(), change.evidence(), change.type().automatic(),
                p.getCreatedAt(), p.getLastSeenAt(), p.getDecidedBy(), p.getDecidedAt(), p.getDecisionNote());
    }
}
