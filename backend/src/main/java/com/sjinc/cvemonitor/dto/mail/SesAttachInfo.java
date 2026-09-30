package com.sjinc.cvemonitor.dto.mail;

import lombok.Builder;
import lombok.Getter;

/**
 * fileName       : SesAttachInfo
 * author         : 최세훈
 * date           : 2025-03-18
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2025-03-18        최세훈       최초 생성
 */

@Getter
public class SesAttachInfo {
    private final String attachPath;   // 첨부파일경로;
    private final String attachFileNm; // 첨부파일명(실제 첨부파일명이 아닌 메일의 첨부파일에 보여질 이름);

    @Builder
    public SesAttachInfo(final String attachPath, final String attachFileNm) {
        this.attachPath = attachPath;
        this.attachFileNm = attachFileNm;
    }
}
