package com.sjinc.securitymonitor.service.ai;

import com.sjinc.securitymonitor.domain.App;
import com.sjinc.securitymonitor.domain.SecureCodeFinding;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewRequest;
import com.sjinc.securitymonitor.dto.ai.SecureCodeReviewTarget;
import com.sjinc.securitymonitor.repository.AppRepository;
import com.sjinc.securitymonitor.repository.SecureCodeFindingRepository;
import com.sjinc.securitymonitor.service.securecode.SecureCodeSnippetBuilder;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 코드 점검 탐지의 AI 판별(파이썬 배치 stage 5) 대기열과 저장 — Semgrep(행안부 규칙)이 잡은 것이 진짜 취약한지 AI가 코드를 보고 판별한다.
 *
 * <p>라이브러리 취약점과 같은 원칙으로 AI는 마지막 수단이다. 대상은 OPEN 중 <b>결정론으로 못 정한 것</b>(연계 추적 판정이 없거나
 * 판정 불가)이면서 등급이 {@code ai.securecode.severities}(기본 HIGH)이거나 규칙이 {@code ai.securecode.extra-rules}인 것뿐이다.
 * 추가 규칙(기본: 난수·취약한 해시·솔트 없는 해시·XXE)은 MEDIUM이지만 판정의 핵심이 "그 코드를 무엇에 쓰는가"(난수가 인증번호용인지 화면 샘플링용인지,
 * SHA-1이 비밀번호용인지 캐시 키용인지)라 값 출처 추적으로는 못 정하고 메서드를 읽으면 대개 보인다 — 오탐이 가장 많고 AI가 가장 잘 가르는 묶음이다.
 * 연계 추적이 클라이언트 값·서버 세팅으로 정한 건은 보내지 않는다. 하드코드된 비밀값 규칙도 보내지 않는다 — 점검 단계에서 값을 {@code ****}로 가려 두므로 AI가 평문인지 {@code ENC(...)}·
 * {@code ${}} 참조인지 구분할 근거가 없다(첫 실행에서 22건이 "규칙이 걸렸으니 취약"만 되풀이했다). 값 자체를 보낼 수는 없다.
 *
 * <p>판별은 화면에 참고로만 보여준다. 처리여부(오탐 등)는 사람이 정한다 — 연계 추적이 안전으로 판정해도 자동 오탐 처리를 하지 않는 것과 같은 이유.
 *
 * <p>소스 코드가 AI로 나가는 유일한 곳이다(사내 정책 예외, 2026-10-06 승인 — 2026-10-07 추가 규칙까지 범위 확대). 걸린 줄을 감싼 메서드(최대 80줄)만 보내고,
 * 보내기 직전에 비밀값을 가린다(SecretMasker — fix-plan의 pom.xml과 같은 방식). 결과는 판별·이유뿐이라 되돌릴 원문이 없다.
 */
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

    private final SecureCodeFindingRepository findingRepository;
    private final AppRepository appRepository;

    /** AI 판별 대상 등급(쉼표 구분). 코드 점검 등급은 HIGH/MEDIUM/LOW다(공통코드 SC_SEVERITY). */
    @Value("#{'${ai.securecode.severities:HIGH}'.split(',')}")
    private List<String> severities;

    /** 등급과 무관하게 AI 판별 대상으로 넣는 규칙(쉼표 구분, 비우면 없음). 위 클래스 설명의 "추가 규칙". */
    @Value("#{'${ai.securecode.extra-rules:kisa-insecure-random,kisa-weak-crypto-hash,kisa-hash-without-salt,kisa-xxe-parser}'.split(',')}")
    private List<String> extraRules;

    /**
     * AI 판별 대상인가 — 비밀값 규칙이 아니고, 등급이 기준 안이거나 추가 규칙이고, 결정론(연계 추적)으로 정하지 못했다. 처리여부와 무관하다
     * (점검 중 코드 문맥을 만들 때는 아직 처리여부를 모른다). 대기열은 여기에 OPEN 조건을 더한다.
     */
    public boolean isTarget(String ruleId, String severity, String traceSafety) {
        return !SecureCodeSnippetBuilder.isSecretRule(ruleId)
                && ((severity != null && severities.contains(severity)) || (ruleId != null && extraRules.contains(ruleId.trim())))
                && (traceSafety == null || TraceSafety.UNKNOWN.name().equals(traceSafety));
    }

    /**
     * 아직 판별하지 않았거나, 판별한 뒤 재점검으로 입력(코드·연계 추적 근거)이 바뀐 탐지. 지워진 앱의 탐지는 뺀다.
     * 점검 때 만든 코드 문맥(메서드)이 없는 탐지는 다음 점검까지 기다린다 — 대상 기준을 넓힌 직후 기존 탐지에는 문맥이 없는데, 화면용 조각(앞뒤 5줄)으로
     * 판별하면 근거가 부족하고, 다음 점검에서 문맥이 생기면 입력이 바뀌어 같은 탐지를 다시 판별(과금)하게 된다.
     */
    @Transactional(readOnly = true)
    public List<SecureCodeReviewTarget> getPendingTargets() {
        Set<Long> appIds = appRepository.findAll().stream().map(App::getId).collect(Collectors.toSet());
        return findingRepository.findByStatus(SecureCodeFinding.OPEN).stream()
                .filter(f -> appIds.contains(f.getAppId()))
                .filter(f -> isTarget(f.getRuleId(), f.getSeverity(), f.getTraceSafety()))
                .filter(f -> f.getAiContext() != null && !f.getAiContext().isBlank())
                .flatMap(f -> {
                    SecureCodeReviewTarget target = toTarget(f);
                    boolean pending = target.code() != null && !target.code().isBlank()
                            && !target.inputHash().equals(f.getAiInputHash());
                    return pending ? Stream.of(target) : Stream.<SecureCodeReviewTarget>empty();
                })
                .toList();
    }

    @Transactional
    public void saveReview(Long findingId, SecureCodeReviewRequest request) {
        if (request.verdict() == null || !VERDICTS.contains(request.verdict())) {
            throw new IllegalArgumentException("판별 값이 올바르지 않습니다: " + request.verdict());
        }
        if (request.confidence() == null || !CONFIDENCES.contains(request.confidence())) {
            throw new IllegalArgumentException("신뢰도 값이 올바르지 않습니다: " + request.confidence());
        }
        String reasoning = request.reasoning() == null ? "" : request.reasoning().strip();
        if (reasoning.isEmpty()) {
            throw new IllegalArgumentException("판별 이유가 비어 있습니다: id=" + findingId);
        }
        if (reasoning.length() > MAX_REASONING_LENGTH) {
            throw new IllegalArgumentException("판별 이유가 너무 깁니다(" + reasoning.length() + "자): id=" + findingId);
        }
        if (request.inputHash() == null || request.inputHash().isBlank()) {
            throw new IllegalArgumentException("inputHash가 없습니다: id=" + findingId);
        }
        SecureCodeFinding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new IllegalArgumentException("탐지 건을 찾을 수 없습니다: id=" + findingId));
        finding.applyAiReview(request.verdict(), request.confidence(), reasoning, request.inputHash(), LocalDateTime.now());
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
     * 배치로 넘길 입력. 코드 문맥이 없으면(대상 기준이 바뀌어 점검 때 만들지 않은 탐지) 화면용 조각을 보낸다.
     * 해시는 가린 뒤의 입력으로 만든다 — 비밀값의 해시를 남기지 않는다(SecretMasker와 같은 이유). 줄 번호는 넣지 않는다 —
     * 위쪽에 한 줄이 추가됐다고 다시 판별(과금)하지 않게(지문에 줄 번호를 넣지 않는 것과 같은 이유).
     */
    static SecureCodeReviewTarget toTarget(SecureCodeFinding f) {
        boolean hasContext = f.getAiContext() != null && !f.getAiContext().isBlank();
        String raw = hasContext ? f.getAiContext() : f.getSnippet();
        int codeStart = hasContext ? f.getAiContextStartLine() : (f.getSnippetStartLine() == null ? 1 : f.getSnippetStartLine());
        String code = raw == null ? null : SecretMasker.mask(raw).text();
        String traceLabel = traceLabel(f.getTraceSafety());
        List<String> evidence = f.getTraceEvidence() == null ? List.of() : List.of(f.getTraceEvidence().split("\n"));
        String hash = sha256(String.join("\u0000", f.getRuleId(), f.getFilePath(), code == null ? "" : code,
                traceLabel == null ? "" : traceLabel, String.join("\n", evidence)));
        return new SecureCodeReviewTarget(f.getId(), f.getRuleId(), f.getKisaCategory(), f.getKisaName(), f.getCwe(),
                f.getSeverity(), f.getMessage(), f.getFilePath(), nz(f.getStartLine()), nz(f.getEndLine()),
                code, codeStart, traceLabel, evidence, hash);
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
