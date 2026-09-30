package com.sjinc.cvemonitor.dto.mail;

import com.amazonaws.services.simpleemail.model.*;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.Builder;
import lombok.Getter;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.thymeleaf.util.ListUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;

/**
 * fileName       : AwsSesDto
 * author         : 최세훈
 * date           : 2025-03-17
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2025-03-17        최세훈       최초 생성
 */
@Getter
public class AwsSesDto {
    private final String from = "sejungcrm@sejung.co.kr";     // 보낸 사람
    private final List<String> to; // 받는 사람
    private final String subject; // 제목
    private final String content; // 본문
    private final List<SesAttachInfo> attachInfo; // 첨부파일

    @Builder
    public AwsSesDto(final List<String> to, final String subject, final String content, final List<SesAttachInfo> attachInfo) {
        this.to = to;
        this.subject = subject;
        this.content = content;
        this.attachInfo = attachInfo;
    }

    public SendRawEmailRequest toSendRawRequestDto() throws Exception {
        Session session = Session.getDefaultInstance(new Properties());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        MimeMessage message = new MimeMessage(session);
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
        mimeMessageHelper.setFrom(from);
        mimeMessageHelper.setTo(InternetAddress.parse(String.join(",", to)));
        mimeMessageHelper.setSubject(subject);
        mimeMessageHelper.setText(content, true);

        if(!ListUtils.isEmpty(attachInfo)) {
            for (SesAttachInfo info : attachInfo) {
                mimeMessageHelper.addAttachment(info.getAttachFileNm(), new File(info.getAttachPath()));
            }
        }

        message.writeTo(outputStream);

        RawMessage rawMessage = new RawMessage(ByteBuffer.wrap(outputStream.toByteArray()));
        return new SendRawEmailRequest(rawMessage);
    }
}
