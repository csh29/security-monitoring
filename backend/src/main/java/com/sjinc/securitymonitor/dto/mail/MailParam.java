package com.sjinc.securitymonitor.dto.mail;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * 메일 발송 요청 파라미터(제목·본문·받는 사람).
 */

@Getter
@Setter
public class MailParam {
    private String subject;
    private String content;
    private List<String> receivers;
}
