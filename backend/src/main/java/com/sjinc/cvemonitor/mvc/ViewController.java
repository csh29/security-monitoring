package com.sjinc.cvemonitor.mvc;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.security.Principal;

/** REST API(controller 패키지)와 구분되는, 화면(뷰)을 반환하는 페이지 컨트롤러. */
@Controller
@RequiredArgsConstructor
public class ViewController {

    private final ResourceLoader resourceLoader;

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/")
    public String home(Principal principal, Model model) {
        model.addAttribute("username", principal != null ? principal.getName() : "");
        model.addAttribute("activeMenu", "home");
        return "home";
    }

    /**
     * 고정 메뉴(취약점 관리/조회, 리포트)와 프로그램 관리 화면에서 등록하는 추가 프로그램을
     * 화면별로 매핑을 추가하지 않고 하나의 경로에서 처리한다.
     * "/program/" 뒤의 URL을 그대로 템플릿 경로(templates/program/그대로.html)로 사용하므로,
     * 화면이 추가돼도 이 컨트롤러를 다시 건드릴 필요 없이 templates/program/ 아래에
     * 같은 이름의 템플릿만 추가하면 된다.
     */
    @GetMapping("/program/{*path}")
    public String programPage(@PathVariable String path, Model model) {
        String view = path.startsWith("/") ? path.substring(1) : path;
        model.addAttribute("activeMenu", view);

        Resource template = resourceLoader.getResource("classpath:/templates/program/" + view + ".html");
        if (!template.exists()) {
            return "program-not-found";
        }
        return "program/" + view;
    }
}
