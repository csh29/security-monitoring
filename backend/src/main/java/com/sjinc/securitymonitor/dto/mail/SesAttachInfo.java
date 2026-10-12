package com.sjinc.securitymonitor.dto.mail;

import lombok.Builder;
import lombok.Getter;

/**
 * SES 메일 첨부파일 한 건(서버 경로와 메일에 보일 파일명).
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
