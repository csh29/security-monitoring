/**
 * 화면 공통 버튼(page-toolbar가 권한에 따라 그린다)에 클릭 핸들러를 건다. 권한이 없어 버튼이 없을 때
 * 직접 걸면 null 오류로 화면 스크립트가 멈추므로, 없는 버튼은 조용히 건너뛴다.
 *
 * 사용법:
 *   PageButtons.bind({ btnSearch: search, btnAdd: addRow, btnSave: saveAll, btnEtc1: exportExcel });
 */
(function (global) {
    function get(id) {
        return document.getElementById(id);
    }

    function bind(handlers) {
        Object.keys(handlers).forEach(function (id) {
            const btn = get(id);
            if (btn) {
                btn.addEventListener('click', handlers[id]);
            }
        });
    }

    global.PageButtons = { bind: bind };
})(window);
