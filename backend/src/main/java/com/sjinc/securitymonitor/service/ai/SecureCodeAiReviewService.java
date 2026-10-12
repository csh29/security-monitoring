package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.ai.SameOriginMember;
import com.sjinc.securitymonitor.dto.ai.SameOriginRef;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewFailure;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewRequest;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewTarget;
import com.sjinc.securitymonitor.dto.securecode.AiRelatedCode;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import com.sjinc.securitymonitor.service.securecode.SameOrigin;
import com.sjinc.securitymonitor.service.securecode.SecureCodeSnippetBuilder;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRuleService;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * 코드 점검 탐지의 AI 판별(파이썬 배치 stage 5) 대기열과 저장 — 소스 코드가 AI로 나가는 유일한 곳이라 감싼 메서드만 비밀값을 가려 보낸다.
 * 엔진은 값의 출처만 확정하고 그 뒤의 검증은 못 보므로 추적이 확정한 HIGH·판정 불가도 보내고, 안전 확정과 가려진 비밀값 규칙은 보내지 않는다.
 * 판별은 참고용이다 — 등급도 처리여부도 바꾸지 않고 사람이 정한다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecureCodeAiReviewService {

    public static final String VULNERABLE = "VULNERABLE";
    public static final String NOT_VULNERABLE = "NOT_VULNERABLE";
    /** 보낸 코드만으로는 판단할 수 없다(입력이 다른 메서드에서 오는데 그 코드가 없는 경우 등). */
    public static final String UNCERTAIN = "UNCERTAIN";
    static final Set<String> VERDICTS = Set.of(VULNERABLE, NOT_VULNERABLE, UNCERTAIN);
    static final Set<String> CONFIDENCES = Set.of("high", "medium", "low");

    /** 판별 이유는 몇 문장을 요청한다. 이보다 길면 코드를 다시 옮겨 적는 등 엉뚱한 응답이라 저장하지 않는다(컬럼 길이와 같다). */
    static final int MAX_REASONING_LENGTH = 2000;
    /** 결론 한 문장. 컬럼 길이와 같다. */
    static final int MAX_SUMMARY_LENGTH = 300;
    /** 예상 공격·조치 방법 각각. 컬럼 길이와 같다. */
    static final int MAX_DETAIL_LENGTH = 1000;

    /** 저장된 관련 코드(JSON) 읽기 — toTarget이 정적이라 주입받지 않고 기본 설정을 쓴다(레코드 읽기뿐이다). */
    private static final ObjectMapper JSON = new ObjectMapper();

    private final SecureCodeFindingRepository findingRepository;
    private final AppRepository appRepository;
    private final TraceRuleService traceRuleService;

    /** AI 판별 대상 등급(쉼표 구분). 코드 점검 등급은 HIGH/MEDIUM/LOW다(공통코드 SC_SEVERITY). */
    @Value("#{'${ai.securecode.severities:HIGH,MEDIUM}'.split(',')}")
    private List<String> severities;

    /** 같은 입력으로 이만큼 실패하면 대기에서 뺀다(입력이 바뀌면 다시 대기). 응답이 늘 잘리거나 저장이 거절되는 건을 배치마다 재과금하지 않게. */
    @Value("${ai.securecode.max-failures:3}")
    private int maxFailures;

    /**
     * 배치 한 번에 판별하는 최대 건수. 대상 기준을 넓히거나 큰 앱을 처음 점검하면 대기가 수천 건이 된다 — 한 번에 다 보내지 않고
     * 높은 등급부터 이만큼만, 나머지는 다음 실행(다음 점검 뒤 자동 실행)이 가져간다.
     */
    @Value("${ai.securecode.max-per-run:200}")
    private int maxPerRun;

    /** 등급과 무관하게 AI 판별 대상으로 넣는 규칙(쉼표 구분, 비우면 없음). 위 클래스 설명의 "추가 규칙". */
    @Value("#{'${ai.securecode.extra-rules:kisa-insecure-random,kisa-weak-crypto-hash,kisa-hash-without-salt,kisa-xxe-parser}'.split(',')}")
    private List<String> extraRules;

    /**
     * AI 판별 대상인가 — 비밀값 규칙·안전 확정이 아니면서 등급이 기준 안이거나, 추가 규칙이거나, 판정 불가(등급 무관)인 것.
     * 점검 중엔 처리여부를 모르므로 여기선 보지 않고, 대기열이 OPEN 조건을 더한다.
     */
    public boolean isTarget(String ruleId, String severity, String traceSafety) {
        if (SecureCodeSnippetBuilder.isSecretRule(ruleId)) return false;
        if (traceSafety != null) {
            if (TraceSafety.UNKNOWN.name().equals(traceSafety)) return true;
            if (confirmedSafe(traceSafety)) return false;
        }
        return (severity != null && severities.contains(severity)) || (ruleId != null && extraRules.contains(ruleId.trim()));
    }

    /** 연계 추적이 안전(서버 세팅·세션 덮어씀·XML에서 결정)으로 확정했는가. 모르는 값(예전 판정 이름)은 확정으로 보지 않는다. */
    private static boolean confirmedSafe(String traceSafety) {
        try {
            return TraceSafety.valueOf(traceSafety).isSafe();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * 아직 판별하지 않았거나, 판별한 뒤 재점검으로 입력(코드·연계 추적 근거)이 바뀐 탐지. 지워진 앱의 탐지는 뺀다.
     * 코드 문맥(메서드)이 없는 탐지는 다음 점검까지 기다린다 — 조각으로 판별하면 근거가 부족하고, 문맥이 생기면 다시 과금된다.
     */
    @Transactional(readOnly = true)
    public List<SecureCodeReviewTarget> getPendingTargets() {
        return getPendingTargets(null, null);
    }

    /**
     * 이번에 판별할 대기 — appId가 있으면 그 앱만(다른 앱 대기까지 과금하지 않게), 높은 등급부터 limit 묶음, 실패 상한 건 제외.
     * 같은 출처(SameOrigin) 대기는 한 묶음으로 실어 같은 원인을 두 번 묻지 않고, 앱의 구조 사실(SecureCodeSystemContext)도 함께 싣는다.
     */
    @Transactional(readOnly = true)
    public List<SecureCodeReviewTarget> getPendingTargets(Long appId, Integer limit) {
        int max = limit == null || limit <= 0 ? maxPerRun : Math.min(limit, maxPerRun);
        Map<Object, List<Pending>> groups = new LinkedHashMap<>();
        candidates(appId).map(this::pending).filter(Objects::nonNull).forEach(p -> {
            String key = SameOrigin.key(p.finding());
            groups.computeIfAbsent(key == null ? p.finding() : key, k -> new ArrayList<>()).add(p);
        });
        if (groups.isEmpty()) return List.of();
        TraceRules rules = loadTraceRules();
        Map<Long, List<String>> contextByApp = new HashMap<>();
        return groups.values().stream()
                .limit(max)
                .map(group -> group.get(0).target()
                        .withSameOrigin(IntStream.range(1, group.size())
                                .mapToObj(i -> member(group.get(i), i <= MAX_SAME_ORIGIN_WITH_CODE)).toList())
                        .withSystemContext(contextByApp.computeIfAbsent(group.get(0).finding().getAppId(),
                                id -> SecureCodeSystemContext.lines(rules, appRepository.findById(id).map(App::getSystemName).orElse(null)))))
                .toList();
    }

    /** 구조 사실의 출처. 못 읽으면 빈 규칙 — 구조 없이 판별한다(판별을 멈출 일은 아니다). */
    private TraceRules loadTraceRules() {
        try {
            return traceRuleService.load();
        } catch (IOException | RuntimeException e) {
            log.warn("추적 규칙을 읽지 못해 AI 판별에 시스템 구조를 싣지 않습니다", e);
            return TraceRules.empty();
        }
    }

    /** 이 앱에 판별할 대기가 있는가(배치를 띄울지 — 대상 전체를 만들지 않고 첫 건에서 멈춘다). */
    @Transactional(readOnly = true)
    public boolean hasPendingTargets(Long appId) {
        return candidates(appId).map(this::pending).anyMatch(Objects::nonNull);
    }

    /** 대기 판단 전 후보 — OPEN·지워지지 않은 앱·코드 문맥 있음·높은 등급부터는 쿼리가, 판별 대상(설정값) 조건은 여기서. */
    private Stream<SecureCodeFinding> candidates(Long appId) {
        return findingRepository.findAiReviewCandidates(appId).stream()
                .filter(f -> isTarget(f.getRuleId(), f.getSeverity(), f.getTraceSafety()));
    }

    private record Pending(SecureCodeFinding finding, SecureCodeReviewTarget target) {
    }

    /** 판별할 대기면 입력과 함께, 아니면 null(이미 지금 입력으로 판별함·상한만큼 실패함·코드 없음). */
    private Pending pending(SecureCodeFinding f) {
        SecureCodeReviewTarget target = toTarget(f);
        boolean pending = target.code() != null && !target.code().isBlank()
                && !target.inputHash().equals(f.getAiInputHash())
                && !gaveUp(f, target.inputHash());
        return pending ? new Pending(f, target) : null;
    }

    /** 같은 출처 지점 — 위험 호출 주변 코드만(메서드 전체를 다 실으면 묶음이 클 때 입력이 커진다). 앞의 몇 개만 코드를 싣는다. */
    private static SameOriginMember member(Pending p, boolean withCode) {
        SecureCodeReviewTarget t = p.target();
        String sink = t.traceEvidence().isEmpty() ? null : t.traceEvidence().get(t.traceEvidence().size() - 1);
        String code = null;
        int codeStart = t.startLine();
        if (withCode && t.code() != null) {
            String[] lines = t.code().split("\n", -1);
            int hit = t.startLine() - t.codeStartLine();
            int from = Math.max(0, hit - SAME_ORIGIN_CONTEXT_LINES);
            int to = Math.min(lines.length, hit + SAME_ORIGIN_CONTEXT_LINES + 1);
            if (from < to) {
                code = String.join("\n", Arrays.asList(lines).subList(from, to));
                codeStart = t.codeStartLine() + from;
            }
        }
        return new SameOriginMember(t.id(), t.inputHash(), t.filePath(), t.startLine(), t.ruleId(), sink, code, codeStart);
    }

    /** 같은 출처 지점마다 싣는 위험 호출 앞뒤 줄 수와, 코드를 싣는 지점 수(넘으면 위치만). */
    static final int SAME_ORIGIN_CONTEXT_LINES = 8;
    static final int MAX_SAME_ORIGIN_WITH_CODE = 5;

    /** 같은 입력으로 상한만큼 실패해 더 보내지 않는가. */
    private boolean gaveUp(SecureCodeFinding f, String inputHash) {
        return f.getAiFailCount() != null && f.getAiFailCount() >= maxFailures && inputHash.equals(f.getAiFailInputHash());
    }

    /** 화면용 — 판별을 포기했는가(지금 입력 기준으로 상한만큼 실패). 실패가 상한에 닿은 건만 해시를 계산한다. */
    public boolean isReviewGivenUp(SecureCodeFinding f) {
        return f.getAiFailCount() != null && f.getAiFailCount() >= maxFailures && gaveUp(f, toTarget(f).inputHash());
    }

    /** 배치가 알린 판별 실패를 센다. 이유는 500자(컬럼 길이)로 자른다. */
    @Transactional
    public void recordFailure(Long findingId, SecureCodeReviewFailure failure) {
        if (failure.inputHash() == null || failure.inputHash().isBlank()) {
            throw new IllegalArgumentException("inputHash가 없습니다: id=" + findingId);
        }
        SecureCodeFinding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new IllegalArgumentException("탐지 건을 찾을 수 없습니다: id=" + findingId));
        String reason = failure.reason() == null ? "" : failure.reason().strip();
        String trimmed = reason.length() > 500 ? reason.substring(0, 500) : reason;
        finding.recordAiFailure(failure.inputHash(), trimmed);
        sameOriginMembers(finding, failure.sameOrigin()).forEach(m -> m.finding().recordAiFailure(m.inputHash(), trimmed));
    }

    private record Member(SecureCodeFinding finding, String inputHash) {
    }

    /**
     * 대표와 함께 판별·실패를 저장할 같은 출처 지점. 배치가 돌려준 id라도 대표와 같은 앱·같은 출처일 때만 받는다 —
     * 엉뚱한 탐지에 판별이 붙지 않게(재점검으로 그사이 출처가 바뀌었으면 그 지점은 다음 배치에서 따로 판별된다).
     */
    private List<Member> sameOriginMembers(SecureCodeFinding representative, List<SameOriginRef> refs) {
        if (refs == null || refs.isEmpty()) return List.of();
        String key = SameOrigin.key(representative);
        if (key == null) return List.of();
        List<Member> members = new ArrayList<>();
        for (SameOriginRef ref : refs) {
            if (ref == null || ref.id() == null || ref.inputHash() == null || ref.inputHash().isBlank()) continue;
            findingRepository.findById(ref.id())
                    .filter(f -> key.equals(SameOrigin.key(f)))
                    .ifPresent(f -> members.add(new Member(f, ref.inputHash())));
        }
        return members;
    }

    @Transactional
    public void saveReview(Long findingId, SecureCodeReviewRequest request) {
        if (request.verdict() == null || !VERDICTS.contains(request.verdict())) {
            throw new IllegalArgumentException("판별 값이 올바르지 않습니다: " + request.verdict());
        }
        if (request.confidence() == null || !CONFIDENCES.contains(request.confidence())) {
            throw new IllegalArgumentException("신뢰도 값이 올바르지 않습니다: " + request.confidence());
        }
        String summary = required(request.summary(), "요약", MAX_SUMMARY_LENGTH, findingId);
        String reasoning = required(request.reasoning(), "판별 이유", MAX_REASONING_LENGTH, findingId);
        String attack = optional(request.attack(), "예상 공격", findingId);
        String fix = optional(request.fix(), "조치 방법", findingId);
        // 취약하다면서 어떻게 공격되는지·어떻게 고치는지가 없으면 사람이 쓸 수 없는 판별이다 — 저장하지 않고 다음 배치에서 다시.
        if (VULNERABLE.equals(request.verdict()) && (attack == null || fix == null)) {
            throw new IllegalArgumentException("취약 판별에 예상 공격·조치 방법이 없습니다: id=" + findingId);
        }
        if (request.inputHash() == null || request.inputHash().isBlank()) {
            throw new IllegalArgumentException("inputHash가 없습니다: id=" + findingId);
        }
        SecureCodeFinding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new IllegalArgumentException("탐지 건을 찾을 수 없습니다: id=" + findingId));
        LocalDateTime now = LocalDateTime.now();
        finding.applyAiReview(request.verdict(), request.confidence(), summary, reasoning, attack, fix, request.inputHash(), now);
        // 같은 출처 지점에도 같은 판별을 저장한다 — 각자 자기 입력 해시로(나중에 한 지점의 코드만 바뀌면 그 지점만 다시 대기가 된다).
        sameOriginMembers(finding, request.sameOrigin()).forEach(m -> m.finding()
                .applyAiReview(request.verdict(), request.confidence(), summary, reasoning, attack, fix, m.inputHash(), now));
    }

    private static String required(String value, String name, int maxLength, Long findingId) {
        String text = value == null ? "" : value.strip();
        if (text.isEmpty()) {
            throw new IllegalArgumentException(name + "이(가) 비어 있습니다: id=" + findingId);
        }
        if (text.length() > maxLength) {
            throw new IllegalArgumentException(name + "이(가) 너무 깁니다(" + text.length() + "자): id=" + findingId);
        }
        return text;
    }

    /** 취약하지 않으면 빈 값으로 온다 — null로 저장한다. */
    private static String optional(String value, String name, Long findingId) {
        String text = value == null ? "" : value.strip();
        if (text.length() > MAX_DETAIL_LENGTH) {
            throw new IllegalArgumentException(name + "이(가) 너무 깁니다(" + text.length() + "자): id=" + findingId);
        }
        return text.isEmpty() ? null : text;
    }

    /**
     * 저장된 판별을 화면에 보여줄 것인가. 재점검으로 코드·근거가 바뀌었으면 옛 판별이라 숨긴다. 비밀값 규칙의 판별도 숨긴다 — 대상에서 빼기 전에
     * 값을 못 본 채 낸 판별이 DB에 남아 있다.
     */
    public static boolean isReviewCurrent(SecureCodeFinding finding) {
        return !SecureCodeSnippetBuilder.isSecretRule(finding.getRuleId())
                && finding.getAiVerdict() != null && finding.getAiInputHash() != null
                && finding.getAiInputHash().equals(toTarget(finding).inputHash());
    }

    /**
     * 배치로 넘길 입력. 코드 문맥이 없으면 화면용 조각을 보낸다.
     * 해시는 가린 뒤의 입력으로 만들어 비밀값 해시를 남기지 않고, 위쪽 줄 추가로 재과금되지 않게 줄 번호는 넣지 않는다.
     */
    static SecureCodeReviewTarget toTarget(SecureCodeFinding f) {
        boolean hasContext = f.getAiContext() != null && !f.getAiContext().isBlank();
        String raw = hasContext ? f.getAiContext() : f.getSnippet();
        int codeStart = hasContext ? f.getAiContextStartLine() : (f.getSnippetStartLine() == null ? 1 : f.getSnippetStartLine());
        String code = raw == null ? null : SecretMasker.mask(raw).text();
        String traceLabel = traceLabel(f.getTraceSafety());
        List<String> evidence = f.getTraceEvidence() == null ? List.of() : List.of(f.getTraceEvidence().split("\n"));
        List<AiRelatedCode> related = relatedCode(f);
        // 관련 코드는 있을 때만 해시에 넣는다 — 넣는 방식이 바뀌기 전에 판별한 탐지가(관련 코드가 없으면) 다시 대기가 되지 않게.
        String relatedText = related.stream().map(r -> r.path() + ":" + r.startLine() + "\n" + r.code()).collect(Collectors.joining("\u0001"));
        String hash = sha256(String.join("\u0000", f.getRuleId(), f.getFilePath(), code == null ? "" : code,
                traceLabel == null ? "" : traceLabel, String.join("\n", evidence)) + (relatedText.isEmpty() ? "" : "\u0000" + relatedText));
        return new SecureCodeReviewTarget(f.getId(), f.getRuleId(), f.getKisaCategory(), f.getKisaName(), f.getCwe(),
                f.getSeverity(), f.getMessage(), f.getFilePath(), nz(f.getStartLine()), nz(f.getEndLine()),
                code, codeStart, traceLabel, evidence, related, hash, List.of(), List.of());
    }

    /** 점검 때 저장한 관련 코드(JSON)를 읽고 비밀값을 가린다. 못 읽으면 없는 것으로(탐지 메서드만 보낸다). */
    private static List<AiRelatedCode> relatedCode(SecureCodeFinding f) {
        if (f.getAiRelatedContext() == null || f.getAiRelatedContext().isBlank()) return List.of();
        try {
            List<AiRelatedCode> stored = JSON.readValue(f.getAiRelatedContext(), new TypeReference<List<AiRelatedCode>>() { });
            return stored.stream()
                    .map(r -> new AiRelatedCode(r.path(), r.startLine(), SecretMasker.mask(r.code()).text(), r.reason()))
                    .toList();
        } catch (Exception e) {
            return List.of();
        }
    }

    /** 예전 값·모르는 값이면 이름 그대로(SecureCodeFindingView와 같은 기준). */
    private static String traceLabel(String safety) {
        if (safety == null) return null;
        try {
            return TraceSafety.valueOf(safety).label();
        } catch (IllegalArgumentException e) {
            return safety;
        }
    }

    private static int nz(Integer value) {
        return value == null ? 0 : value;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
