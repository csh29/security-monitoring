package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.domain.CveSummary;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.dto.ai.CveSummaryRequest;
import com.sjinc.cvemonitor.dto.ai.CveSummaryTarget;
import com.sjinc.cvemonitor.repository.CveSummaryRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * NVD 설명의 한국어 요약(CveSummary) 대기열과 저장. 요약은 파이썬 배치의 3단계가 Haiku로 만든다.
 *
 * <p>AI 판단(HIGH/CRITICAL 중 자동판정 불가 건만)과 달리 등급·판정 결과와 무관하게 설명이 있는 모든 CVE가 대상이다
 * — 화면에서 설명을 읽는 건 등급과 상관없기 때문이다. 대신 CVE ID당 한 번만 요약한다.
 */
@Service
@RequiredArgsConstructor
public class CveSummaryService {

    /** 2~3문장 요약을 요청하므로 이보다 길면 요약이 아니라 번역·잡담이 섞인 응답이다. 저장하지 않고 거절한다. */
    static final int MAX_SUMMARY_LENGTH = 1000;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final CveSummaryRepository cveSummaryRepository;

    /** 아직 요약이 없거나, 요약한 뒤 NVD가 설명을 바꾼 CVE들. */
    public List<CveSummaryTarget> getPendingSummaryTargets() {
        Map<String, String> descriptions = currentDescriptions();
        Map<String, String> summarizedHashes = cveSummaryRepository.findAllById(descriptions.keySet()).stream()
                .collect(Collectors.toMap(CveSummary::getCveId, CveSummary::getDescriptionHash));

        return descriptions.entrySet().stream()
                .map(e -> new CveSummaryTarget(e.getKey(), e.getValue(), CveSummary.hashOf(e.getValue())))
                .filter(target -> !target.descriptionHash().equals(summarizedHashes.get(target.cveId())))
                .toList();
    }

    @Transactional
    public void saveSummary(CveSummaryRequest request) {
        if (request.cveId() == null || !vulnerabilityRepository.existsByCveId(request.cveId())) {
            throw new IllegalArgumentException("등록되지 않은 CVE입니다: " + request.cveId());
        }
        String summary = request.summary() == null ? "" : request.summary().strip();
        if (summary.isEmpty()) {
            throw new IllegalArgumentException("요약이 비어 있습니다: " + request.cveId());
        }
        if (summary.length() > MAX_SUMMARY_LENGTH) {
            throw new IllegalArgumentException("요약이 너무 깁니다(" + summary.length() + "자): " + request.cveId());
        }
        if (request.descriptionHash() == null || request.descriptionHash().isBlank()) {
            throw new IllegalArgumentException("descriptionHash가 없습니다: " + request.cveId());
        }

        cveSummaryRepository.findById(request.cveId()).ifPresentOrElse(
                existing -> existing.update(summary, request.descriptionHash()),
                () -> cveSummaryRepository.save(CveSummary.builder()
                        .cveId(request.cveId())
                        .summary(summary)
                        .descriptionHash(request.descriptionHash())
                        .summarizedAt(LocalDateTime.now())
                        .build()));
    }

    /** 화면 표시용: CVE ID → 요약. 요약이 없는 CVE는 맵에 없다. */
    public Map<String, String> findSummaries(Collection<String> cveIds) {
        return cveSummaryRepository.findAllById(cveIds).stream()
                .collect(Collectors.toMap(CveSummary::getCveId, CveSummary::getSummary));
    }

    /**
     * CVE ID별 현재 설명. 같은 CVE라도 앱마다 스캔 시점이 달라 행마다 설명이 다를 수 있어서, NVD 수정 시각이
     * 가장 최근인 행의 설명을 쓴다(오래 재스캔 안 한 앱의 옛 설명으로 요약하지 않도록).
     */
    private Map<String, String> currentDescriptions() {
        Comparator<Vulnerability> newestFirst = Comparator.comparing(Vulnerability::getNvdLastModified,
                Comparator.nullsLast(Comparator.reverseOrder()));
        return vulnerabilityRepository.findByDescriptionIsNotNull().stream()
                .filter(v -> !v.getDescription().isBlank())
                .sorted(newestFirst)
                .collect(Collectors.toMap(Vulnerability::getCveId, Vulnerability::getDescription,
                        (newer, older) -> newer));
    }
}
