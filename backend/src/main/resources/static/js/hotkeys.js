/**
 * 화면 공통 펑션키 — F3 조회, F4 신규, F5 삭제, F9 저장, F12 초기화.
 *
 * 화면은 버튼에 data-hotkey="F3"처럼 표시만 하면 된다. 키를 누르면 그 표시가 붙은 버튼을
 * 클릭한 것과 똑같이 동작하므로(비활성 버튼이면 무시), 화면 JS가 따로 키 처리를 할 필요가 없다.
 * 같은 키가 붙은 버튼이 여럿이면(공통코드관리의 그룹/상세 신규·저장·삭제처럼) 지금 포커스가 있는
 * .panel 안의 버튼을, 없으면 먼저 나오는 버튼을 누른다.
 *
 * 홈 화면(탭 셸)에서 탭 버튼 등을 클릭해 포커스가 바깥에 있을 때도 키가 먹도록, 이 문서에
 * 해당 버튼이 없으면 지금 보이는 탭 iframe으로 넘긴다.
 *
 * 버튼 글자 뒤에는 키를 자동으로 붙인다(예: "조회" → "조회[F3]") — 화면 마크업에는 "조회"만 쓴다.
 *
 * F3(찾기)·F5(새로고침)·F12(개발자 도구)의 브라우저 기본 동작은 막는다. Ctrl/Shift/Alt와 함께
 * 누른 키는 건드리지 않으므로 새로고침은 Ctrl+R·Ctrl+F5, 개발자 도구는 Ctrl+Shift+I로 쓰면 된다.
 */
(function () {
    if (window.triggerHotkey) {
        return;
    }

    const HOTKEYS = ['F3', 'F4', 'F5', 'F9', 'F12'];

    function isUsable(btn) {
        return !btn.disabled && btn.offsetParent !== null;
    }

    function findButton(key) {
        const buttons = Array.from(document.querySelectorAll('[data-hotkey="' + key + '"]')).filter(isUsable);
        if (buttons.length === 0) {
            return null;
        }
        const active = document.activeElement;
        const panel = active && active.closest ? active.closest('.panel') : null;
        return buttons.find(function (btn) { return panel && panel.contains(btn); }) || buttons[0];
    }

    window.triggerHotkey = function (key) {
        const btn = findButton(key);
        if (btn) {
            btn.click();
            return true;
        }
        const frame = Array.from(document.querySelectorAll('.tab-iframe')).find(function (f) {
            return f.style.display === 'block';
        });
        return !!(frame && frame.contentWindow && frame.contentWindow.triggerHotkey
            && frame.contentWindow.triggerHotkey(key));
    };

    document.addEventListener('keydown', function (e) {
        if (HOTKEYS.indexOf(e.key) === -1 || e.ctrlKey || e.shiftKey || e.altKey || e.metaKey) {
            return;
        }
        e.preventDefault();
        if (e.repeat) {
            return;
        }
        window.triggerHotkey(e.key);
    });

    // 버튼 글자에 단축키를 붙인다(예: "조회[F3]").
    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('[data-hotkey]').forEach(function (btn) {
            btn.textContent = btn.textContent.trim() + '[' + btn.dataset.hotkey + ']';
        });
    });
})();
