package com.sjinc.cvemonitor.service.ai;

import com.sjinc.cvemonitor.domain.CveSummary;
import com.sjinc.cvemonitor.domain.Vulnerability;
import com.sjinc.cvemonitor.dto.ai.CveSummaryRequest;
import com.sjinc.cvemonitor.dto.ai.CveSummaryTarget;
import com.sjinc.cvemonitor.repository.CveSummaryRepository;
import com.sjinc.cvemonitor.repository.VulnerabilityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CveSummaryServiceTest {

    private VulnerabilityRepository vulnerabilityRepository;
    private CveSummaryRepository cveSummaryRepository;
    private CveSummaryService service;

    @BeforeEach
    void setUp() {
        vulnerabilityRepository = mock(VulnerabilityRepository.class);
        cveSummaryRepository = mock(CveSummaryRepository.class);
        service = new CveSummaryService(vulnerabilityRepository, cveSummaryRepository);
    }

    private static Vulnerability vuln(String cveId, String description, LocalDateTime nvdLastModified) {
        return Vulnerability.builder().cveId(cveId).description(description).nvdLastModified(nvdLastModified).build();
    }

    private static CveSummary summarized(String cveId, String description) {
        return CveSummary.builder().cveId(cveId).summary("요약").descriptionHash(CveSummary.hashOf(description)).build();
    }

    @Test
    void 같은_CVE가_여러_행에_있어도_한_번만_대기에_오른다() {
        when(vulnerabilityRepository.findByDescriptionIsNotNull()).thenReturn(List.of(
                vuln("CVE-1", "desc", null), vuln("CVE-1", "desc", null)));
        when(cveSummaryRepository.findAllById(anyCollection())).thenReturn(List.of());

        assertThat(service.getPendingSummaryTargets()).extracting(CveSummaryTarget::cveId).containsExactly("CVE-1");
    }

    @Test
    void 요약한_설명이_그대로면_대기가_아니고_설명이_바뀌면_다시_대기다() {
        when(vulnerabilityRepository.findByDescriptionIsNotNull()).thenReturn(List.of(
                vuln("CVE-SAME", "same", null), vuln("CVE-CHANGED", "new text", null)));
        when(cveSummaryRepository.findAllById(anyCollection())).thenReturn(List.of(
                summarized("CVE-SAME", "same"), summarized("CVE-CHANGED", "old text")));

        assertThat(service.getPendingSummaryTargets()).extracting(CveSummaryTarget::cveId).containsExactly("CVE-CHANGED");
    }

    @Test
    void 행마다_설명이_다르면_NVD_수정시각이_최근인_설명으로_요약한다() {
        when(vulnerabilityRepository.findByDescriptionIsNotNull()).thenReturn(List.of(
                vuln("CVE-1", "old", LocalDateTime.of(2024, 1, 1, 0, 0)),
                vuln("CVE-1", "new", LocalDateTime.of(2025, 1, 1, 0, 0)),
                vuln("CVE-1", "unknown", null)));
        when(cveSummaryRepository.findAllById(anyCollection())).thenReturn(List.of());

        assertThat(service.getPendingSummaryTargets()).singleElement()
                .satisfies(t -> {
                    assertThat(t.description()).isEqualTo("new");
                    assertThat(t.descriptionHash()).isEqualTo(CveSummary.hashOf("new"));
                });
    }

    @Test
    void 빈_요약이나_너무_긴_요약은_저장하지_않는다() {
        when(vulnerabilityRepository.existsByCveId("CVE-1")).thenReturn(true);
        String hash = CveSummary.hashOf("desc");

        assertThatThrownBy(() -> service.saveSummary(new CveSummaryRequest("CVE-1", "  ", hash)))
                .isInstanceOf(IllegalArgumentException.class);
        String tooLong = "가".repeat(CveSummaryService.MAX_SUMMARY_LENGTH + 1);
        assertThatThrownBy(() -> service.saveSummary(new CveSummaryRequest("CVE-1", tooLong, hash)))
                .isInstanceOf(IllegalArgumentException.class);
        verify(cveSummaryRepository, never()).save(any());
    }

    @Test
    void 등록되지_않은_CVE의_요약은_거절한다() {
        when(vulnerabilityRepository.existsByCveId("CVE-X")).thenReturn(false);

        assertThatThrownBy(() -> service.saveSummary(new CveSummaryRequest("CVE-X", "요약", "hash")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void 기존_요약이_있으면_새_요약과_해시로_갱신한다() {
        CveSummary existing = summarized("CVE-1", "old");
        when(vulnerabilityRepository.existsByCveId("CVE-1")).thenReturn(true);
        when(cveSummaryRepository.findById("CVE-1")).thenReturn(Optional.of(existing));

        service.saveSummary(new CveSummaryRequest("CVE-1", " 새 요약 ", CveSummary.hashOf("new")));

        assertThat(existing.getSummary()).isEqualTo("새 요약");
        assertThat(existing.getDescriptionHash()).isEqualTo(CveSummary.hashOf("new"));
    }
}
