package com.sjinc.securitymonitor.controller;

import com.sjinc.securitymonitor.dto.mail.MailParam;
import com.sjinc.securitymonitor.service.mail.MailService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * fileName       : MailController
 * author         : 최세훈
 * date           : 26. 9. 30.
 * description    :
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 26. 9. 30.        최세훈       최초 생성
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mail")
public class MailController {

    private final MailService mailService;

    @RequestMapping(value = "/sendMail", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<?> sendMail(HttpServletRequest request, @Validated @RequestBody MailParam param) throws Exception {
        return mailService.sendEmail(param);
    }

}
