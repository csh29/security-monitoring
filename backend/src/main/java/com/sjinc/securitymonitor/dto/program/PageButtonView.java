package com.sjinc.securitymonitor.dto.program;

import com.sjinc.securitymonitor.domain.ProgramButton;

/** 화면 툴바에 그릴 버튼 하나(fragments/page-toolbar가 그린다). hotkey가 null이면 단축키 없음. */
public record PageButtonView(String id, String label, String hotkey, String cssClass) {

    public static PageButtonView of(ProgramButton button, String label) {
        return new PageButtonView(button.getElementId(), label, button.getHotkey(), button.getCssClass());
    }
}
