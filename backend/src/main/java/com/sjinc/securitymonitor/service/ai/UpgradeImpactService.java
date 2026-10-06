package com.sjinc.securitymonitor.service.ai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sjinc.securitymonitor.domain.FixPlanChange;
import com.sjinc.securitymonitor.domain.UpgradeImpact;
import com.sjinc.securitymonitor.domain.VersionJump;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest.BreakingChange;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactRequest.Source;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactTarget;
import com.sjinc.securitymonitor.dto.ai.UpgradeImpactView;
import com.sjinc.securitymonitor.repository.FixPlanChangeRepository;
import com.sjinc.securitymonitor.repository.UpgradeImpactRepository;
import com.sjinc.securitymonitor.service.maven.VersionJumpClassifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 업그레이드 영향 분석(stage 4)의 대기열·저장·조회.
 *
 * <p>AI 분석 대상은 마이너·메이저 점프뿐이다. 패치 점프는 하위 호환이 원칙이라 릴리스 노트를 읽힐 이유가 없고,
 * UNKNOWN(다운그레이드·해석 불가)은 분석이 아니라 사람이 fix-plan을 다시 봐야 하는 건이다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UpgradeImpactService {

    static final List<VersionJump> ANALYZED_JUMPS = List.of(VersionJump.MINOR, VersionJump.MAJOR);

    private static final Set<String> STATUSES =
            Set.of(UpgradeImpact.ANALYZED, UpgradeImpact.NO_SOURCE, UpgradeImpact.FETCH_FAILED);
    private static final Set<String> RISKS = Set.of("LOW", "MEDIUM", "HIGH");
    private static final Set<String> CONFIDENCES = Set.of("high", "medium", "low");
    private static final Set<String> SOURCE_KINDS =
            Set.of("GITHUB_RELEASE", "GITLAB_RELEASE", "CHANGELOG", "JIRA", "OFFICIAL_DOC");

    private static final int MAX_SYMBOLS = 10;
    private static final int MAX_SYMBOL_LENGTH = 200;

    private final FixPlanChangeRepository fixPlanChangeRepository;
    private final UpgradeImpactRepository upgradeImpactRepository;
    private final ObjectMapper objectMapper;

    public List<UpgradeImpactTarget> getPendingTargets() {
        return fixPlanChangeRepository.findPendingImpactTargets(ANALYZED_JUMPS, UpgradeImpact.FETCH_FAILED);
    }

    /**
     * 배치가 보낸 결과를 정규화해 저장한다(같은 키면 덮어쓴다). 요청 자체가 틀리면(없는 키, 정해지지 않은 상태값,
     * 근거 없는 ANALYZED) 400으로 거절하고, 항목 단위로 틀린 것(출처가 근거 목록에 없는 breaking change)은 그 항목만 버린다.
     */
    @Transactional
    public void saveImpact(UpgradeImpactRequest request) {
        Normalized normalized = normalize(request);
        // 아무 좌표나 저장되면 대기열·화면과 무관한 행이 쌓인다. 요약(CveSummaryService)이 미등록 CVE를 거절하는 것과 같다.
        if (!fixPlanChangeRepository.existsByCoordinateAndFromVersionAndToVersion(
                request.coordinate(), request.fromVersion(), request.toVersion())) {
            throw new IllegalArgumentException("fix-plan에 없는 업그레이드입니다: "
                    + request.coordinate() + " " + request.fromVersion() + " → " + request.toVersion());
        }

        UpgradeImpact impact = upgradeImpactRepository
                .findByCoordinateAndFromVersionAndToVersion(request.coordinate(), request.fromVersion(), request.toVersion())
                .orElseGet(() -> UpgradeImpact.of(request.coordinate(), request.fromVersion(), request.toVersion()));
        impact.apply(normalized.status(), normalized.risk(), normalized.confidence(),
                toJson(normalized.breakingChanges()), toJson(normalized.requiredActions()),
                toJson(normalized.testFocus()), toJson(normalized.sources()), normalized.note());
        upgradeImpactRepository.save(impact);
    }

    /** 분석 결과를 정규화한 값. DB 저장 전 단계라 Spring 없이 테스트할 수 있게 분리했다. */
    record Normalized(String status, String risk, String confidence, List<BreakingChange> breakingChanges,
                      List<String> requiredActions, List<String> testFocus, List<Source> sources, String note) {
    }

    static Normalized normalize(UpgradeImpactRequest request) {
        if (isBlank(request.coordinate()) || isBlank(request.fromVersion()) || isBlank(request.toVersion())) {
            throw new IllegalArgumentException("좌표와 from/to 버전은 필수입니다.");
        }
        if (!STATUSES.contains(request.status())) {
            throw new IllegalArgumentException("정해지지 않은 상태값입니다: " + request.status());
        }
        String note = isBlank(request.note()) ? null : request.note().trim();
        if (!UpgradeImpact.ANALYZED.equals(request.status())) {
            // 근거를 못 모은 건에 위험도·조치가 붙어 있으면 모델 추측이 섞인 것이다 — 분석 필드를 모두 비운다.
            return new Normalized(request.status(), null, null, List.of(), List.of(), List.of(), List.of(), note);
        }

        List<Source> sources = nullToEmpty(request.sources()).stream()
                .filter(Objects::nonNull)
                .filter(s -> SOURCE_KINDS.contains(s.kind()) && isHttpUrl(s.url()))
                .toList();
        if (sources.isEmpty()) {
            throw new IllegalArgumentException("근거 문서 없이 분석 결과를 저장할 수 없습니다.");
        }
        if (!RISKS.contains(request.risk()) || !CONFIDENCES.contains(request.confidence())) {
            throw new IllegalArgumentException("위험도·신뢰도 값이 올바르지 않습니다: " + request.risk() + "/" + request.confidence());
        }

        // 근거 목록에 없는 URL을 출처로 단 breaking change는 모델이 지어냈을 수 있다. 파이썬도 거르지만 한 번 더 막는다.
        Set<String> sourceUrls = sources.stream().map(Source::url).collect(Collectors.toSet());
        List<BreakingChange> requestedChanges = nullToEmpty(request.breakingChanges());
        List<BreakingChange> breakingChanges = requestedChanges.stream()
                .filter(Objects::nonNull)
                .filter(c -> !isBlank(c.summary()) && sourceUrls.contains(c.sourceUrl()))
                .map(c -> new BreakingChange(c.summary().trim(), c.sourceUrl(), normalizeSymbols(c.symbols())))
                .toList();
        int dropped = requestedChanges.size() - breakingChanges.size();
        if (dropped > 0) {
            note = appendNote(note, "출처가 근거 문서에 없는 breaking change " + dropped + "건을 버렸습니다.");
        }

        return new Normalized(UpgradeImpact.ANALYZED,
                adjustRisk(request.risk(), request.fromVersion(), request.toVersion()),
                adjustConfidence(request.confidence(), sources),
                breakingChanges, trimAll(request.requiredActions()), trimAll(request.testFocus()), sources, note);
    }

    /** 메이저 점프는 릴리스 노트에 breaking change가 안 보여도 HIGH로 본다 — 노트가 빠뜨렸을 가능성이 가장 큰 경우다. */
    static String adjustRisk(String risk, String fromVersion, String toVersion) {
        return VersionJumpClassifier.classify(fromVersion, toVersion) == VersionJump.MAJOR ? "HIGH" : risk;
    }

    /**
     * 근거가 JIRA 이슈 목록뿐이면 신뢰도를 medium 이하로 낮춘다. 이슈 목록은 "무엇이 고쳐졌나"는 알려주지만
     * "무엇이 깨지나"(하위 호환이 깨지는 변경)는 따로 표시되지 않는 경우가 많다.
     */
    static String adjustConfidence(String confidence, List<Source> sources) {
        boolean jiraOnly = sources.stream().allMatch(s -> "JIRA".equals(s.kind()));
        return jiraOnly && "high".equals(confidence) ? "medium" : confidence;
    }

    /** fix-plan 조회용 — 변경 항목들에 해당하는 분석 결과를 (좌표|from|to) 키로 돌려준다. */
    @Transactional(readOnly = true)
    public Map<String, UpgradeImpactView> findImpacts(List<FixPlanChange> changes) {
        return changes.stream()
                .map(c -> upgradeImpactRepository.findByCoordinateAndFromVersionAndToVersion(
                        c.getCoordinate(), c.getFromVersion(), c.getToVersion()))
                .flatMap(Optional::stream)
                .collect(Collectors.toMap(
                        u -> key(u.getCoordinate(), u.getFromVersion(), u.getToVersion()),
                        this::toView,
                        (first, second) -> first));
    }

    public static String key(String coordinate, String fromVersion, String toVersion) {
        return coordinate + "|" + fromVersion + "|" + toVersion;
    }

    private UpgradeImpactView toView(UpgradeImpact impact) {
        return new UpgradeImpactView(impact.getStatus(), impact.getRisk(), impact.getConfidence(),
                fromJson(impact.getBreakingChangesJson(), new TypeReference<>() {}),
                fromJson(impact.getRequiredActionsJson(), new TypeReference<>() {}),
                fromJson(impact.getTestFocusJson(), new TypeReference<>() {}),
                fromJson(impact.getSourcesJson(), new TypeReference<>() {}),
                impact.getNote(), impact.getAnalyzedAt());
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("영향 분석 결과를 JSON으로 바꾸지 못했습니다.", e);
        }
    }

    private <T> List<T> fromJson(String json, TypeReference<List<T>> type) {
        if (isBlank(json)) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, type);
        } catch (JsonProcessingException e) {
            // 저장은 이 서비스만 하므로 여기 오면 데이터가 손으로 수정된 것이다. 조회 화면 전체를 죽이지 않고 비워서 보여준다.
            log.warn("영향 분석 JSON을 읽지 못했습니다: {}", e.getMessage());
            return List.of();
        }
    }

    /** 대조용 이름. 공백을 떼고 중복을 없애고, 한 항목에 너무 많거나 긴 이름은 모델이 문장을 넣은 것이라 자른다. */
    static List<String> normalizeSymbols(List<String> symbols) {
        return nullToEmpty(symbols).stream()
                .filter(s -> !isBlank(s))
                .map(String::trim)
                .filter(s -> s.length() <= MAX_SYMBOL_LENGTH && !s.contains(" "))
                .distinct()
                .limit(MAX_SYMBOLS)
                .toList();
    }

    private static List<String> trimAll(List<String> values) {
        return nullToEmpty(values).stream().filter(v -> !isBlank(v)).map(String::trim).toList();
    }

    private static <T> List<T> nullToEmpty(List<T> values) {
        return values == null ? List.of() : values;
    }

    private static String appendNote(String note, String addition) {
        return note == null ? addition : note + "\n" + addition;
    }

    private static boolean isHttpUrl(String url) {
        return url != null && (url.startsWith("https://") || url.startsWith("http://"));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
