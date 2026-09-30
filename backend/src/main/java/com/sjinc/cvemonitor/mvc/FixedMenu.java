package com.sjinc.cvemonitor.mvc;

import com.sjinc.cvemonitor.domain.ProgramButton;
import com.sjinc.cvemonitor.dto.program.PageButtonView;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Program 테이블에 없는 사이드바 고정 메뉴. 로그인만으로 열리는 화면이라 프로그램 관리·사용자별
 * 권한관리로 버튼을 정할 수 없어서, 화면명과 툴바 버튼을 여기 고정해 둔다.
 * name은 sidebar.html의 고정 메뉴 라벨과 같은 값이어야 한다(그쪽은 템플릿에 박혀 있다).
 */
enum FixedMenu {
    VULNERABILITY_MNG("vulnerability-mng", "취약점 관리", ProgramButton.SEARCH, ProgramButton.SAVE),
    VULNERABILITY_SEARCH("vulnerability-search", "취약점 조회", ProgramButton.SEARCH, ProgramButton.RESET),
    SCAN_HISTORY("scan-history", "스캔 이력", ProgramButton.SEARCH, ProgramButton.RESET),
    FIX_PLAN("fix-plan", "조치안", ProgramButton.SEARCH, ProgramButton.RESET),
    REPORT("report", "리포트");

    private final String view;
    private final String programNm;
    private final List<ProgramButton> buttons;

    FixedMenu(String view, String programNm, ProgramButton... buttons) {
        this.view = view;
        this.programNm = programNm;
        this.buttons = List.of(buttons);
    }

    static Optional<FixedMenu> of(String view) {
        return Arrays.stream(values()).filter(menu -> menu.view.equals(view)).findFirst();
    }

    String programNm() {
        return programNm;
    }

    List<PageButtonView> pageButtons() {
        return buttons.stream().map(button -> PageButtonView.of(button, button.getDefaultLabel())).toList();
    }
}
