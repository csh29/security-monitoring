package com.sjinc.cvemonitor.service.mail;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.model.SendRawEmailResult;
import com.sjinc.cvemonitor.dto.mail.AwsSesDto;
import com.sjinc.cvemonitor.dto.mail.MailParam;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class MailService {

    private final AmazonSimpleEmailService amazonSimpleEmailService;


    public ResponseEntity<?> sendEmail(MailParam param) throws Exception {
        final AwsSesDto senderDto = AwsSesDto.builder()
                .to(param.getReceivers())
                .subject(param.getSubject())
                .content(param.getContent())
                .build();

        final SendRawEmailResult sendRawEmailResult = amazonSimpleEmailService.sendRawEmail(senderDto.toSendRawRequestDto());

        return sendingResultMustSuccess(sendRawEmailResult);
    }

    private ResponseEntity<?> sendingResultMustSuccess(final SendRawEmailResult sendRawEmailResult) throws Exception {
        if (sendRawEmailResult.getSdkHttpMetadata().getHttpStatusCode() != 200) {
            log.error("{}", sendRawEmailResult.getSdkResponseMetadata().toString());
            throw new Exception(sendRawEmailResult.getSdkResponseMetadata().toString());
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

}