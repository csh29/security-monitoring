/**
 * 화면 공통 펑션키(F3 조회, F4 신규, F5 삭제, F9 저장, F12 초기화). data-hotkey가 붙은 버튼을 클릭한 것처럼
 * 동작하고, 여럿이면 포커스가 있는 .panel 안의 버튼을, 문서에 없으면 보이는 탭 iframe으로 넘긴다. 버튼 글자 뒤에
 * 키를 자동으로 붙이며, 수식키 없이 누른 F키의 브라우저 기본 동작은 막는다.
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
