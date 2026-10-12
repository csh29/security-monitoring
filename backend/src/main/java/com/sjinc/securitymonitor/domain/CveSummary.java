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
 * NVD 영어 설명의 한국어 요약(파이썬 배치가 만든다). 같은 CVE가 여러 행에 걸려 중복 과금되지 않게 CVE ID당 한 건이다.
 * 재요약 기준은 descriptionHash다 — nvdLastModified는 설명과 무관한 수정에도 바뀌어 불필요한 재요약을 부른다.
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
