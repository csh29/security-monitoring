package com.sjinc.securitymonitor.domain;

/**
 * 화면 공통 버튼(툴바)의 종류 — 프로그램별 사용 버튼과 사용자별 허용 버튼을 이 단위로 정한다.
 * id는 화면 JS가 핸들러를 거는 엘리먼트 id, 순서는 툴바 순서이고, 기타1~5의 라벨은 프로그램 관리에서 입력한 이름을 쓴다.
 */
public enum ProgramButton {
    SEARCH("btnSearch", "조회", "F3", ""),
    NEW("btnAdd", "신규", "F4", ""),
    SAVE("btnSave", "저장", "F9", "primary"),
    DELETE("btnDelete", "삭제", "F5", "danger"),
    RESET("btnReset", "초기화", "F12", ""),
    ETC1("btnEtc1", "기타1", null, ""),
    ETC2("btnEtc2", "기타2", null, ""),
    ETC3("btnEtc3", "기타3", null, ""),
    ETC4("btnEtc4", "기타4", null, ""),
    ETC5("btnEtc5", "기타5", null, "");

    private final String elementId;
    private final String defaultLabel;
    private final String hotkey;
    private final String cssClass;

    ProgramButton(String elementId, String defaultLabel, String hotkey, String cssClass) {
        this.elementId = elementId;
        this.defaultLabel = defaultLabel;
        this.hotkey = hotkey;
        this.cssClass = cssClass;
    }

    public String getElementId() { return elementId; }
    public String getDefaultLabel() { return defaultLabel; }
    public String getHotkey() { return hotkey; }
    public String getCssClass() { return cssClass; }
}
