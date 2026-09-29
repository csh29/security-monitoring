/**
 * 화면 공통 버튼(fragments/page-toolbar가 권한에 따라 그린다)에 클릭 핸들러를 건다.
 *
 * 버튼은 사용자·프로그램마다 있을 수도 없을 수도 있어서, 화면이
 * document.getElementById('btnSave').addEventListener(...)로 직접 걸면 권한이 없는 사용자에게서
 * null 오류로 화면 스크립트 전체가 멈춘다. 대신 이걸 쓴다 — 없는 버튼은 조용히 건너뛴다.
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
