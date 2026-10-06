package com.sjinc.securitymonitor.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

/**
 * NVD 영어 설명(description)의 한국어 요약. 파이썬 배치가 Haiku로 만든다.
 *
 * <p>Vulnerability 행이 아니라 CVE ID 하나에 한 건이다 — 같은 CVE가 여러 앱·아티팩트 행에 걸리는 게
 * 흔해서(Vulnerability 복합 유니크 주석 참고) 행마다 두면 같은 문장을 여러 번 요약(과금)하게 된다.
 *
 * <p>descriptionHash는 "어느 설명을 요약했는가"다. NVD가 설명을 고치면 해시가 달라져 다시 요약 대기가 된다.
 * nvdLastModified로 판단하지 않는 이유: NVD는 설명과 무관한 CPE·참조 링크 수정에도 그 값을 바꿔서,
 * 설명이 그대로인데 다시 요약하게 된다.
 */
@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveSummary {

    @Id
    private String cveId;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String summary;

    @Column(length = 64)
    private String descriptionHash;

    private LocalDateTime summarizedAt;

    public void update(String summary, String descriptionHash) {
        this.summary = summary;
        this.descriptionHash = descriptionHash;
        this.summarizedAt = LocalDateTime.now();
    }

    /** 설명 원문의 SHA-256(hex). 요약 대기 판단과 배치가 되돌려주는 값의 기준이 같아야 해서 여기 한 곳에 둔다. */
    public static String hashOf(String description) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(description.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256을 쓸 수 없습니다.", e); // 모든 JDK에 있는 알고리즘이라 실제로는 안 난다
        }
    }
}
