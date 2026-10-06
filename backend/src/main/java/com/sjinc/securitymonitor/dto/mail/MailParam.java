package com.sjinc.securitymonitor.dto.mail;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * fileName       : MailParam
 * author         : 최세훈
 * date           : 2025-03-17
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2025-03-17        최세훈       최초 생성
 */

@Getter
@Setter
public class MailParam {
    private String subject;
    private String content;
    private List<String> receivers;
}
