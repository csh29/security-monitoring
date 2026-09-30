package com.sjinc.cvemonitor.mvc;

import com.sjinc.cvemonitor.domain.Program;
import com.sjinc.cvemonitor.dto.program.PageButtonView;
import com.sjinc.cvemonitor.repository.ProgramRepository;
import com.sjinc.cvemonitor.security.ProgramAccessGuard;
import com.sjinc.cvemonitor.service.program.ProgramService;
import com.sjinc.cvemonitor.service.vulnerability.VulnerabilityService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/** REST API(controller 패키지)와 구분되는, 화면(뷰)을 반환하는 페이지 컨트롤러. */
@Controller
@RequiredArgsConstructor
public class ViewController {

    private final ResourceLoader resourceLoader;
    private final VulnerabilityService vulnerabilityService;
    private final ProgramRepository programRepository;
    private final ProgramAccessGuard programAccess;
    private final ProgramService programService;

    /** 대시보드 막대그래프에 보여줄 프로젝트 수. */
    private static final int DASHBOARD_TOP_APPS = 5;

    /**
     * 화면 이름으로 허용하는 형태. 경로에서 받은 값을 그대로 템플릿 경로에 이어 붙이므로,
     * {@code ..}나 {@code /}가 섞여 들어오면 templates/program/ 바깥의 템플릿을 렌더링하려는
     * 시도가 된다(Spring Security의 기본 방화벽이 대부분 먼저 막아주지만, 그 방어에만 기대지 않는다).
     * 실제 화면 이름은 전부 소문자·숫자·하이픈이라 이 패턴으로 충분하다.
     */
    private static final Pattern VIEW_NAME = Pattern.compile("[a-z0-9-]+");

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/")
    public String home(Principal principal, Model model) {
        model.addAttribute("username", principal != null ? principal.getName() : "");
        model.addAttribute("activeMenu", "home");
        model.addAttribute("totalOpenVulnerabilities", vulnerabilityService.countOpenVulnerabilities());
        model.addAttribute("averageResolutionRate", vulnerabilityService.getAverageResolutionRate());
        model.addAttribute("openCriticalRate", vulnerabilityService.getOpenCriticalRate());
        model.addAttribute("appVulnerabilityCounts",
                vulnerabilityService.getTopOpenVulnerabilityCountsByApp(DASHBOARD_TOP_APPS));
        return "home";
    }

    /**
     * 고정 메뉴(취약점 관리/조회, 스캔 이력, 리포트)와 프로그램 관리 화면에서 등록하는 추가 프로그램을
     * 화면별로 매핑을 추가하지 않고 하나의 경로에서 처리한다.
     * "/program/" 뒤의 URL을 그대로 템플릿 경로(templates/program/그대로.html)로 사용하므로,
     * 화면이 추가돼도 이 컨트롤러를 다시 건드릴 필요 없이 templates/program/ 아래에
     * 같은 이름의 템플릿만 추가하면 된다.
     */
    @GetMapping("/program/{*path}")
    public String programPage(@PathVariable String path, Principal principal, Model model) {
        String view = path.startsWith("/") ? path.substring(1) : path;
        if (!VIEW_NAME.matcher(view).matches()) {
            return "program-not-found";
        }

        // 화면 이름은 Program.programId와 같은 값이다(사이드바의 추가 프로그램이 곧 이 URL을 연다).
        // 그래서 "이 화면이 Program 테이블에 등록돼 있으면 그 프로그램 권한이 있어야 열 수 있다"로
        // 판단하면, 사이드바 노출 기준(SidebarModelAdvice)과 화면 접근 기준이 한 데이터로 일치한다.
        // 등록돼 있지 않은 화면은 고정 메뉴(취약점 관리/조회, 스캔 이력, 리포트)라 로그인만으로 열린다.
        //
        // API는 @RequiresProgram이 이미 막고 있어서 데이터가 새지는 않았지만, 권한 없는 사용자에게
        // 빈 화면을 열어주면 "메뉴에는 없는데 주소로는 열린다"가 되어 접근 제어 기준이 화면과 API에서
        // 갈린다. 기준이 갈리면 나중에 어느 쪽이 맞는지 아무도 모르게 된다.
        if (programRepository.existsById(view)
                && !programAccess.check(principal != null ? principal.getName() : null, view)) {
            throw new AccessDeniedException("이 화면에 접근할 권한이 없습니다: " + view);
        }

        model.addAttribute("activeMenu", view);
        // 화면 첫 줄(fragments/page-toolbar)의 프로그램명과 공통 버튼. 등록된 프로그램은 프로그램 관리에서
        // 바꾼 이름이 사이드바·탭 제목과 똑같이 따라오도록 DB 값을 쓰고, 버튼은 "프로그램이 쓰는 버튼 ∩
        // 이 사용자에게 허용된 버튼"이다. 고정 메뉴는 FixedMenu에 적어 둔 값을 쓴다.
        String username = principal != null ? principal.getName() : null;
        Optional<FixedMenu> fixedMenu = FixedMenu.of(view);
        List<PageButtonView> pageButtons = programService.getPageButtons(username, view)
                .orElseGet(() -> fixedMenu.map(FixedMenu::pageButtons).orElse(List.of()));
        model.addAttribute("programNm", programRepository.findById(view)
                .map(Program::getProgramNm)
                .orElseGet(() -> fixedMenu.map(FixedMenu::programNm).orElse("")));
        model.addAttribute("pageButtons", pageButtons);

        Resource template = resourceLoader.getResource("classpath:/templates/program/" + view + ".html");
        if (!template.exists()) {
            return "program-not-found";
        }
        return "program/" + view;
    }
}
