package com.sjinc.securitymonitor.mvc;

import com.sjinc.securitymonitor.domain.Program;
import com.sjinc.securitymonitor.service.program.ProgramService;
import lombok.RequiredArgsConstructor;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.security.Principal;
import java.util.List;

/** 사이드바 메뉴 — 로그인한 사용자가 권한을 가진 프로그램을 그룹별(라이브러리 취약점·시큐어코딩·관리)로 나눠 얹는다. */
@ControllerAdvice(assignableTypes = ViewController.class)
@RequiredArgsConstructor
public class SidebarModelAdvice {

    private final ProgramService programService;

    @ModelAttribute
    public void sidebarPrograms(Principal principal, Model model) {
        List<Program> programs = programService.getAccessiblePrograms(principal != null ? principal.getName() : null);
        model.addAttribute("libPrograms", group(programs, Program.GROUP_LIB));
        model.addAttribute("securePrograms", group(programs, Program.GROUP_SECURE));
        model.addAttribute("extraPrograms", group(programs, Program.GROUP_MNG));
    }

    private static List<Program> group(List<Program> programs, String group) {
        return programs.stream().filter(p -> group.equals(p.sidebarGroup())).toList();
    }
}
