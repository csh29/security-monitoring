package com.sjinc.cvemonitor.mvc;

import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.service.program.ProgramService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.security.Principal;
import java.util.List;

/**
 * sidebar.html의 고정 메뉴(홈/취약점 관리/취약점 조회/리포트)는 그대로 두고,
 * 로그인한 사용자가 권한을 가진 추가 프로그램만 "extraPrograms" 모델 속성으로 얹어준다.
 */
@ControllerAdvice(assignableTypes = ViewController.class)
@RequiredArgsConstructor
public class SidebarModelAdvice {

    private final ProgramService programService;

    @ModelAttribute("extraPrograms")
    public List<Program> extraPrograms(Principal principal) {
        return programService.getAccessiblePrograms(principal != null ? principal.getName() : null);
    }
}
