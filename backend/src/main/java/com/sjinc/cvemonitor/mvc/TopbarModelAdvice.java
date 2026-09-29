package com.sjinc.cvemonitor.mvc;

import com.sjinc.cvemonitor.dto.user.UserResponse;
import com.sjinc.cvemonitor.service.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.security.Principal;

/**
 * topbar.html 우측의 로그인 사용자 표시("사용자명(아이디)")를 "loginUserLabel" 모델 속성으로 얹는다.
 * 상단바는 모든 화면이 같은 조각을 쓰므로, 화면 컨트롤러마다 넣지 않고 여기 한 곳에서 채운다.
 */
@ControllerAdvice(assignableTypes = ViewController.class)
@RequiredArgsConstructor
public class TopbarModelAdvice {

    private final UserService userService;

    @ModelAttribute("loginUserLabel")
    public String loginUserLabel(Principal principal) {
        if (principal == null) {
            return "";
        }
        return userService.getUser(principal.getName())
                .map(UserResponse::userNm)
                .map(userNm -> userNm + "(" + principal.getName() + ")")
                .orElse(principal.getName());
    }
}
