/**
 * 공통 모달(.modal-backdrop > .modal)을 제목줄(.modal 안의 첫 h3)로 끌어서 옮길 수 있게 한다.
 * 모든 화면이 싣는 loading-overlay.html에서 한 번 불러오므로, 모달을 새로 만들어도 화면 코드는 할 일이 없다
 * — common-ui.css의 모달 뼈대(.modal-backdrop/.modal)와 제목 h3만 지키면 된다.
 *
 * - 위치는 transform으로만 옮긴다. 백드롭이 flex로 가운데 정렬하는 기본 배치를 건드리지 않아서,
 *   모달이 닫히면(백드롭의 .open이 빠지면) transform만 지워 다음에 열 때 다시 가운데에서 뜬다.
 * - 제목줄이 화면 밖으로 나가 다시 잡을 수 없게 되는 일이 없도록 화면 안으로 제한한다.
 * - 끌다가 모달 밖(백드롭 위)에서 놓으면 브라우저가 그 click을 백드롭 클릭으로 보내서, 화면들의
 *   "백드롭을 누르면 닫기"가 동작해 모달이 닫혀 버린다. 실제로 옮겼으면 바로 다음 click 하나를 삼킨다.
 */
(function () {
    /** 제목줄이 화면 안에 최소 이만큼은 남아 있게 한다(px). */
    const KEEP_VISIBLE = 60;

    function handleOf(target) {
        const handle = target.closest('.modal h3');
        if (!handle) {
            return null;
        }
        const modal = handle.closest('.modal');
        // 모달 안의 다른 h3(본문 소제목)는 손잡이가 아니다 — 모달의 첫 h3만.
        return modal && modal.querySelector('h3') === handle ? { handle: handle, modal: modal } : null;
    }

    function currentOffset(modal) {
        return { x: parseFloat(modal.dataset.dragX) || 0, y: parseFloat(modal.dataset.dragY) || 0 };
    }

    function setOffset(modal, x, y) {
        modal.dataset.dragX = x;
        modal.dataset.dragY = y;
        modal.style.transform = 'translate(' + x + 'px, ' + y + 'px)';
    }

    function swallowNextClick() {
        function swallow(e) {
            e.stopPropagation();
            e.preventDefault();
        }
        window.addEventListener('click', swallow, { capture: true, once: true });
        // 놓은 자리에서 click이 안 생기는 경우(다른 요소 위 등)에 다음 정상 클릭까지 먹지 않도록 곧 해제한다.
        setTimeout(function () { window.removeEventListener('click', swallow, { capture: true }); }, 0);
    }

    document.addEventListener('pointerdown', function (e) {
        if (e.button !== 0) {
            return;
        }
        const found = handleOf(e.target);
        if (!found) {
            return;
        }
        e.preventDefault(); // 끄는 동안 글자가 선택되지 않게
        const modal = found.modal;
        const start = { x: e.clientX, y: e.clientY };
        const origin = currentOffset(modal);
        const rect = modal.getBoundingClientRect();
        // 현재 위치 기준으로 움직일 수 있는 범위(제목줄이 화면 안에 KEEP_VISIBLE만큼은 남게).
        const bounds = {
            minX: origin.x - rect.left - rect.width + KEEP_VISIBLE,
            maxX: origin.x + (window.innerWidth - rect.left) - KEEP_VISIBLE,
            minY: origin.y - rect.top,
            maxY: origin.y + (window.innerHeight - rect.top) - KEEP_VISIBLE
        };
        let moved = false;

        function onMove(ev) {
            const dx = ev.clientX - start.x;
            const dy = ev.clientY - start.y;
            if (!moved && Math.abs(dx) + Math.abs(dy) < 3) {
                return; // 살짝 누른 것까지 이동으로 보지 않는다
            }
            moved = true;
            setOffset(modal,
                Math.min(bounds.maxX, Math.max(bounds.minX, origin.x + dx)),
                Math.min(bounds.maxY, Math.max(bounds.minY, origin.y + dy)));
        }

        function onUp() {
            document.removeEventListener('pointermove', onMove);
            document.removeEventListener('pointerup', onUp);
            document.removeEventListener('pointercancel', onUp);
            modal.classList.remove('is-dragging');
            if (moved) {
                swallowNextClick();
            }
        }

        modal.classList.add('is-dragging');
        document.addEventListener('pointermove', onMove);
        document.addEventListener('pointerup', onUp);
        document.addEventListener('pointercancel', onUp);
    });

    // 모달이 닫히면(백드롭의 .open 제거) 옮긴 위치를 지워, 다음에 열 때 다시 가운데에서 뜨게 한다.
    new MutationObserver(function (mutations) {
        mutations.forEach(function (m) {
            const backdrop = m.target;
            if (!backdrop.classList.contains('modal-backdrop') || backdrop.classList.contains('open')) {
                return;
            }
            backdrop.querySelectorAll('.modal').forEach(function (modal) {
                delete modal.dataset.dragX;
                delete modal.dataset.dragY;
                modal.style.transform = '';
            });
        });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'], subtree: true });
})();
