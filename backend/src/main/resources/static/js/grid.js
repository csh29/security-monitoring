/**
 * 공통 그리드 렌더러. 헤더와 행을 columns 정의로 그리며, 공통 CSS는 /css/grid.css를 <link>로 싣는다.
 *
 * 사용법:
 *   Grid.renderHeader(thead, columns, { initialMessage });
 *   Grid.render(tbody, columns, rows, options);
 *   Grid.getRows(tbody)            // 모든 행 데이터
 *   Grid.getRow(tbody, rowIndex)   // rowIndex(0부터, 안내 행 제외) 번째 행 데이터. 없으면 null
 *   Grid.removeRows(tbody, rows)   // 행 데이터에 해당하는 tr을 지운다
 *   Grid.addRow(tbody, { focus })  // 맨 위에 빈 행을 넣고 첫 입력칸(또는 focus col.id)에 커서. 새 행 데이터를 돌려준다
 *
 * 행 데이터: 원본 row에 입력 셀의 현재 값을 col.id로 덮어쓴 새 객체(화면은 tr._fields를 직접 읽지 않는다).
 *   - text/number/password : 앞뒤 공백을 뺀 문자열(number도 문자열)
 *   - checkbox             : 'Y' / 'N'
 *   - select               : 선택된 value
 *   - _rowIndex            : getRow에 넘기는 행 순번
 *   - _isNew               : 저장 전 신규 행이면 true
 *   - _selected            : row-select로 선택된 행이면 true
 *
 * columns: [{ id, label, width, align, cursor, className, headerClassName, type, render(value, row, td, tr), title(value, row) }]
 *   - id        : row에서 꺼낼 속성명. textContent 또는 입력 엘리먼트 값으로 들어간다.
 *   - label     : 헤더 th 텍스트. 생략하면 빈 th.
 *   - width     : 컬럼 폭(숫자면 px, 문자열은 그대로). 화면 CSS 대신 이 값으로 통일한다.
 *   - align     : td의 text-align. 헤더는 항상 가운데 정렬이라 영향받지 않는다.
 *   - cursor    : td의 cursor 스타일(예: 'pointer').
 *   - className : td 클래스. headerClassName이 없으면 th에도 적용된다.
 *   - headerClassName : th에만 다른 클래스를 줄 때 지정.
 *   - render    : (value, row, td, tr) → Node는 append, 문자열/숫자는 textContent로 넣는다.
 *   - type      : render 없이 입력 엘리먼트를 선언적으로 만든다.
 *       - 'text' | 'number' | 'password' (기본 'text') : <input>. 값은 row[col.id].
 *       - 'checkbox' : Y/N 체크박스. 신규 행은 col.defaultChecked(기본 true), col.checked(value,row,tr)로 대체 가능.
 *       - 'select'   : col.options(row|배열) 또는 col.optionsQuery(공통코드 그룹, com-cd.js 필요)로 옵션을 채운다.
 *       - 'row-select': "삭제"용 행 선택 체크박스. tr의 'selected'만 토글하며 헤더에 전체 선택이 붙는다.
 *     엘리먼트는 tr._fields[col.id]에 저장된다. 보조 옵션: col.disabled(value,row), col.placeholder,
 *     col.readOnly(value,row)(disabled는 행 클릭이 막히므로 클릭이 필요하면 readOnly), col.stopPropagation(row-select 전용).
 *   - title     : true면 텍스트 값을, 함수면 (value, row) 리턴값을 툴팁으로 쓴다.
 *   - onDblClick: (value, row) 더블클릭 콜백.
 *   - display   : select 보기 모드. (value, label, row) 결과를 보여주다 누르면 select로 바뀐다.
 *
 * type 셀은 엔터로 다음 셀, 위/아래 방향키로 같은 열 셀로 이동한다(select는 방향키 이동 없음).
 *
 * options:
 *   - emptyMessage : rows가 없을 때 문구.
 *   - buildRow(tr, row) : tr 생성 직후(셀 채우기 전) 호출 — dataset/class 지정용.
 *   - onRowClick(tr, row) : 행 클릭 콜백(row는 행 데이터). 클릭한 행에는 'current' 강조가 자동으로 붙는다.
 *   - virtual : true면 100행 이상일 때 보이는 행만 붙인다. 행 높이가 일정하고 부모가 세로 스크롤 영역일 때만 켠다.
 *
 * 모든 그리드 공통:
 *   - 현재 셀에 'cell-current' 테두리를 표시한다.
 *   - 우클릭 메뉴: 셀 복사 / 행 복사(탭 구분) / 엑셀 다운로드. 보이는 값 기준이며 id 없는 컬럼은 빠진다.
 *   - 헤더를 끌어 컬럼 순서를 바꾼다. 컬럼 배열을 제자리에서 바꿔 재조회해도 유지된다.
 *   - 헤더 오른쪽 경계를 끌어 컬럼 폭을 바꾼다(col.width에 남아 재조회해도 유지).
 *   - 체크박스 셀은 체크박스 주변 빈 곳을 눌러도 체크가 바뀐다.
 */
(function (global) {
    /**
     * width/align 같은 컬럼별 스타일을 화면 <style> 태그 대신 이 inline style로 적용한다.
     * 숫자(px) width는 최소 폭도 된다 — 컬럼이 많아 화면보다 넓으면 컬럼을 찌그러뜨리지 않고
     * 그리드에 가로 스크롤이 생긴다(ensureScrollWrapper).
     */
    function applyColumnStyle(cell, col, isHeader) {
        if (col.width !== undefined && col.width !== null) {
            cell.style.width = typeof col.width === 'number' ? col.width + 'px' : col.width;
            if (typeof col.width === 'number') {
                cell.style.minWidth = col.width + 'px';
            }
        }
        if (col.align && !isHeader) {
            cell.style.textAlign = col.align;
        }
    }

    /**
     * select 셀의 보기 모드(col.display). 평소엔 col.display(value, label, row)가 돌려준 노드(뱃지 등)를
     * 보여주고, 셀을 누르면 select로 바뀌었다가 포커스가 빠지면 새 값으로 다시 그린다. select 엘리먼트는
     * 숨기기만 하고 tr._fields에 그대로 두므로 getRows/getRow는 보통 select 셀과 똑같이 현재 값을 읽는다.
     */
    function attachDisplayMode(td, select, col, row) {
        const view = document.createElement('span');
        view.className = 'grid-cell-view';
        td.insertBefore(view, select);

        function showView() {
            const option = select.options[select.selectedIndex];
            const rendered = col.display(select.value, option ? option.textContent : '', row);
            view.innerHTML = '';
            if (rendered instanceof Node) {
                view.appendChild(rendered);
            } else if (rendered !== undefined && rendered !== null) {
                view.textContent = rendered;
            }
            select.style.display = 'none';
            view.style.display = '';
            td.classList.remove('grid-editor-cell'); // 보기 모드는 일반 셀처럼 padding을 쓴다
        }

        function showEditor() {
            view.style.display = 'none';
            select.style.display = '';
            td.classList.add('grid-editor-cell');
            select.focus();
            // 한 번 누르면 바로 목록이 열리게 한다(지원하지 않는 브라우저는 포커스만 된 채로 둔다).
            if (typeof select.showPicker === 'function') {
                try { select.showPicker(); } catch (e) { /* 사용자 동작 밖이면 거부될 수 있다 */ }
            }
        }

        td.style.cursor = 'pointer';
        td.addEventListener('click', function () {
            if (select.style.display === 'none') {
                showEditor();
            }
        });
        select.addEventListener('change', showView);
        select.addEventListener('blur', showView);
        showView();
    }

    /** col.type 하나로 편집 가능한 셀의 입력 엘리먼트를 만든다 — buildRow의 render 분기 대신 쓰인다. */
    function createFieldElement(col, value, row, tr) {
        if (col.type === 'row-select') {
            const chk = document.createElement('input');
            chk.type = 'checkbox';
            return chk;
        }

        if (col.type === 'checkbox') {
            const chk = document.createElement('input');
            chk.type = 'checkbox';
            chk.checked = typeof col.checked === 'function'
                ? !!col.checked(value, row, tr)
                : (row ? value === 'Y' : col.defaultChecked !== false);
            return chk;
        }

        if (col.type === 'select') {
            const select = document.createElement('select');
            const options = typeof col.options === 'function' ? col.options(row) : (col.options || []);
            options.forEach(function (opt) {
                const option = document.createElement('option');
                option.value = opt.value;
                option.textContent = opt.label;
                select.appendChild(option);
            });
            const selected = row ? value : col.defaultValue;
            if (selected !== undefined && selected !== null) {
                select.value = String(selected);
            }
            return select;
        }

        const input = document.createElement('input');
        input.type = col.type;
        input.value = (value === null || value === undefined) ? '' : value;
        if (col.placeholder) {
            input.placeholder = typeof col.placeholder === 'function' ? col.placeholder(row) : col.placeholder;
        }
        return input;
    }

    /**
     * 그리드가 화면보다 넓어지면 가로 스크롤이 생기도록 table을 .grid-scroll로 한 번 감싼다.
     * 화면이 이미 스크롤 영역(.grid-wrap — 취약점 관리처럼 세로 스크롤을 직접 두는 화면)으로
     * 감싸 두었으면 그대로 둔다.
     */
    function ensureScrollWrapper(table) {
        const parent = table && table.parentElement;
        if (!parent || parent.classList.contains('grid-scroll') || parent.classList.contains('grid-wrap')) {
            return;
        }
        const wrapper = document.createElement('div');
        wrapper.className = 'grid-scroll';
        parent.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    }

    /** 세로 스크롤 영역의 최소 높이. 화면이 이보다 좁으면 그리드 대신 페이지가 스크롤된다. */
    const MIN_SCROLL_HEIGHT = 200;

    /**
     * .grid-scroll의 세로 한도를 시작 위치부터 화면 아래 끝까지로 맞춰, 페이지가 아닌 그리드 본문만 스크롤되고
     * 헤더가 고정되게 한다. 조회영역처럼 늦게 그려지는 요소로 위치가 바뀌므로 그릴 때마다·창 크기 변경 때마다 다시 계산한다.
     */
    function fitScrollHeights() {
        document.querySelectorAll('.grid-scroll').forEach(function (wrapper) {
            const main = wrapper.closest('.area-main');
            const scrollTop = main ? main.scrollTop : 0;
            const bottomGap = main ? (parseFloat(getComputedStyle(main).paddingBottom) || 0) : 0;
            const top = wrapper.getBoundingClientRect().top + scrollTop;
            const available = Math.floor(window.innerHeight - top - bottomGap);
            wrapper.style.maxHeight = Math.max(available, MIN_SCROLL_HEIGHT) + 'px';
        });
    }

    let fitScheduled = false;
    /** 한 번에 여러 그리드를 그려도 레이아웃이 잡힌 뒤 한 번만 계산한다. */
    function scheduleFitScrollHeights() {
        if (fitScheduled) {
            return;
        }
        fitScheduled = true;
        global.requestAnimationFrame(function () {
            fitScheduled = false;
            fitScrollHeights();
        });
    }

    global.addEventListener('resize', scheduleFitScrollHeights);

    /** 첫 조회 결과가 오기 전까지 tbody에 보여줄 기본 문구. */
    const DEFAULT_INITIAL_MESSAGE = '조회 중입니다...';

    /**
     * columns 정의로 thead 한 줄을 만든다. tbody가 비어 있으면 첫 조회 전까지 보일 안내 행(문구는
     * options.initialMessage, colspan은 컬럼 수)을 넣고, 이미 행이 있으면 건드리지 않는다.
     */
    function renderHeader(thead, columns, options) {
        options = options || {};
        ensureScrollWrapper(thead.closest('table'));
        thead.innerHTML = '';
        const tr = document.createElement('tr');

        columns.forEach(function (col) {
            const th = document.createElement('th');
            const className = col.headerClassName || col.className;
            if (className) {
                th.className = className;
            }
            applyColumnStyle(th, col, true);
            th.textContent = col.label || '';
            if (col.type === 'row-select') {
                const selectAll = createSelectAll(thead);
                th.insertBefore(selectAll, th.firstChild);
                bindCheckCell(th, selectAll, false);
            }
            th.draggable = true;
            th.appendChild(createResizer(thead, th, col));
            tr.appendChild(th);
        });

        thead.appendChild(tr);
        thead._gridColumns = columns; // 헤더 드래그로 컬럼 순서를 바꿀 때 쓴다(moveColumn)
        if (!thead._gridDragBound) {
            bindColumnDrag(thead);
        }

        const table = thead.closest('table');
        const tbody = table && table.tBodies[0];
        if (tbody) {
            tbody._gridColumns = columns; // Grid.addRow가 쓴다
        }
        if (tbody && tbody.rows.length === 0) {
            clearAndAppendMessage(tbody, columns.length, options.initialMessage || DEFAULT_INITIAL_MESSAGE);
        }
        scheduleFitScrollHeights();
    }

    // ── 컬럼 폭 조절 ───────────────────────────────────────────────────────

    const MIN_COLUMN_WIDTH = 40;

    /** 헤더 오른쪽 경계의 손잡이. 끄는 동안은 순서 바꾸기 드래그를 끄고, 바꾼 폭은 컬럼 정의에 남겨 다시 조회해도 유지한다. */
    function createResizer(thead, th, col) {
        const handle = document.createElement('span');
        handle.className = 'grid-col-resizer';
        handle.addEventListener('click', function (e) { e.stopPropagation(); }); // 헤더 클릭(전체 선택 등)으로 넘기지 않는다
        handle.addEventListener('mousedown', function (e) {
            e.preventDefault();
            e.stopPropagation();
            const startX = e.clientX;
            const startWidth = th.getBoundingClientRect().width;
            let pending = null;
            th.draggable = false;
            document.body.classList.add('grid-col-resizing');

            function move(ev) {
                pending = Math.max(MIN_COLUMN_WIDTH, Math.round(startWidth + ev.clientX - startX));
                global.requestAnimationFrame(function () {
                    if (pending !== null) setColumnWidth(thead, th.cellIndex, col, pending);
                    pending = null;
                });
            }
            function up() {
                document.removeEventListener('mousemove', move);
                document.removeEventListener('mouseup', up);
                th.draggable = true;
                document.body.classList.remove('grid-col-resizing');
            }
            document.addEventListener('mousemove', move);
            document.addEventListener('mouseup', up);
        });
        return handle;
    }

    /** 헤더와 그 열의 모든 셀(가상 스크롤로 떼어 둔 행 포함) 폭을 바꾼다. */
    function setColumnWidth(thead, index, col, width) {
        col.width = width;
        applyColumnStyle(thead.rows[0].cells[index], col, true);
        const table = thead.closest('table');
        // 폭이 자유로운 컬럼이 없으면 표가 100%를 채우려 남는 폭을 모든 컬럼에 나눠 준다 — 그때는 표 폭을 컬럼 합으로 둔다.
        const flexible = (thead._gridColumns || []).some(function (c) { return typeof c.width !== 'number'; });
        if (table) table.style.width = flexible ? '' : 'auto';
        const tbody = table && table.tBodies[0];
        if (!tbody) return;
        dataRows(tbody).forEach(function (tr) {
            if (tr.cells[index]) applyColumnStyle(tr.cells[index], col, false);
        });
    }

    // ── 체크박스 셀 ─────────────────────────────────────────────────────────

    /** 체크박스 셀은 체크박스 주변 빈 곳을 눌러도 체크가 바뀐다. stopRow면 행 클릭(onRowClick)으로 넘기지 않는다. */
    function bindCheckCell(cell, chk, stopRow) {
        cell.classList.add('grid-check-cell');
        cell.addEventListener('click', function (e) {
            if (e.target === chk || chk.disabled) return;
            // click()은 합성 클릭이 행까지 한 번 더 올라가므로 값만 바꾸고 change를 보낸다.
            chk.checked = !chk.checked;
            chk.dispatchEvent(new Event('change', { bubbles: true }));
            if (stopRow) e.stopPropagation();
        });
    }

    // ── 행 선택 전체 체크/해제 ─────────────────────────────────────────────

    /**
     * row-select 헤더의 전체 선택 체크박스. 누르면 전체 행(가상 스크롤로 떼어 둔 행 포함)의 선택을 맞추고,
     * 행을 하나씩 고르면 syncSelectAll이 전체·일부(indeterminate)·없음으로 따라간다. 비활성 체크박스 행은 건드리지 않는다.
     */
    function createSelectAll(thead) {
        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.className = 'grid-select-all';
        chk.title = '전체 선택/해제';
        chk.addEventListener('change', function () {
            const table = thead.closest('table');
            const tbody = table && table.tBodies[0];
            if (!tbody) {
                return;
            }
            dataRows(tbody).forEach(function (tr) {
                const field = tr._selectField;
                if (field && !field.disabled) {
                    field.checked = chk.checked;
                    tr.classList.toggle('selected', chk.checked);
                }
            });
            syncSelectAll(tbody);
        });
        return chk;
    }

    /** 헤더 전체 선택 체크박스를 행 선택 상태에 맞춘다 — 다시 조회·행 추가·삭제·행 하나 선택 뒤에 부른다. */
    function syncSelectAll(tbody) {
        const table = tbody && tbody.closest('table');
        const chk = table && table.tHead ? table.tHead.querySelector('input.grid-select-all') : null;
        if (!chk) {
            return;
        }
        const fields = dataRows(tbody)
            .map(function (tr) { return tr._selectField; })
            .filter(function (field) { return field && !field.disabled; });
        const checked = fields.filter(function (field) { return field.checked; }).length;
        chk.checked = fields.length > 0 && checked === fields.length;
        chk.indeterminate = checked > 0 && checked < fields.length;
        chk.disabled = fields.length === 0;
    }

    // ── 헤더 드래그로 컬럼 순서 바꾸기 ─────────────────────────────────────

    /** tr 안에서 from번째 셀을 to번째 자리로 옮긴다(to는 from을 뺀 뒤 기준 위치). */
    function moveCell(tr, from, to) {
        const cell = tr.cells[from];
        if (!cell) {
            return;
        }
        cell.remove();
        tr.insertBefore(cell, tr.cells[to] || null);
    }

    /**
     * 컬럼 하나를 from → to로 옮긴다. 화면이 넘긴 컬럼 정의 배열 자체를 제자리에서 바꾸는 게 핵심이다 — 화면은 같은
     * COLUMNS를 다시 조회(render)·신규(addRow)에도 그대로 넘기므로, 한 번 옮긴 순서가 그 화면을 떠날 때까지 유지된다.
     * 이미 그려진 행은 다시 그리지 않고 셀만 옮긴다(입력 중인 값이 날아가지 않게). 새로고침하면 원래 순서로 돌아간다.
     */
    function moveColumn(thead, from, to) {
        if (from === to) {
            return;
        }
        const table = thead.closest('table');
        const tbody = table && table.tBodies[0];
        // 헤더와 행이 같은 배열을 쓰는 게 보통이지만, 다른 배열이면 둘 다 같은 순서로 맞춘다.
        [thead._gridColumns, tbody && tbody._gridColumns]
            .filter(function (columns, i, all) { return columns && all.indexOf(columns) === i; })
            .forEach(function (columns) {
                columns.splice(to, 0, columns.splice(from, 1)[0]);
            });

        moveCell(thead.rows[0], from, to);
        if (tbody) {
            dataRows(tbody).forEach(function (tr) {
                moveCell(tr, from, to);
                // 엔터·방향키 이동 순서(왼쪽→오른쪽)도 새 화면 순서를 따르게 다시 정렬한다.
                if (tr._orderedFields) {
                    tr._orderedFields.sort(function (a, b) {
                        return a.closest('td').cellIndex - b.closest('td').cellIndex;
                    });
                }
            });
        }
    }

    /** 헤더(th) 드래그앤드롭. 놓을 자리는 마우스가 대상 th의 왼쪽/오른쪽 절반 중 어디에 있는지로 정하고 선으로 보여준다. */
    function bindColumnDrag(thead) {
        let from = -1;

        function clearMarks() {
            Array.from(thead.querySelectorAll('th')).forEach(function (th) {
                th.classList.remove('drag-before', 'drag-after', 'dragging');
            });
        }

        /** 드롭하면 들어갈 위치(옮기기 전 기준 0..n). 대상 th가 아니면 -1. */
        function dropPosition(e) {
            const th = e.target.closest('th');
            if (!th || th.parentElement.parentElement !== thead) {
                return { th: null, pos: -1 };
            }
            const rect = th.getBoundingClientRect();
            const before = e.clientX < rect.left + rect.width / 2;
            return { th: th, before: before, pos: th.cellIndex + (before ? 0 : 1) };
        }

        thead.addEventListener('dragstart', function (e) {
            const th = e.target.closest('th');
            if (!th) {
                return;
            }
            from = th.cellIndex;
            th.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', ''); // Firefox는 데이터를 넣어야 드래그가 시작된다
        });
        thead.addEventListener('dragover', function (e) {
            if (from < 0) {
                return; // 다른 그리드나 바깥에서 끌어온 것은 받지 않는다
            }
            const target = dropPosition(e);
            if (!target.th) {
                return;
            }
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            Array.from(thead.querySelectorAll('th')).forEach(function (th) {
                th.classList.toggle('drag-before', th === target.th && target.before);
                th.classList.toggle('drag-after', th === target.th && !target.before);
            });
        });
        thead.addEventListener('drop', function (e) {
            const target = dropPosition(e);
            if (from >= 0 && target.pos >= 0) {
                e.preventDefault();
                moveColumn(thead, from, target.pos > from ? target.pos - 1 : target.pos);
            }
            clearMarks();
            from = -1;
        });
        thead.addEventListener('dragend', function () {
            clearMarks();
            from = -1;
        });
        thead._gridDragBound = true;
    }

    function clearAndAppendMessage(tbody, colspan, message) {
        stopVirtual(tbody);
        tbody.innerHTML = '';
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.className = 'empty';
        td.colSpan = colspan;
        td.textContent = message;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }

    /**
     * tr을 그 tbody 안에서 유일한 'current'(강조 표시) 행으로 만들고 onRowClick도 호출한다.
     * 클릭으로 행이 바뀔 때와, 엔터로 다음 행으로 넘어가 행이 바뀔 때 둘 다 이걸 쓴다 —
     * 어느 쪽으로 행이 바뀌었든 강조색과 onRowClick 부수효과가 항상 같이 따라오게 하기 위함.
     */
    function markRowCurrent(tbody, tr) {
        // 붙어 있는 행만이 아니라 전체 행에서 지운다 — 가상 스크롤(virtual)로 화면 밖에 떼어 둔 행도 다시 붙으면 강조가 남아 있다.
        dataRows(tbody).forEach(function (other) {
            if (other !== tr) {
                other.classList.remove('current');
            }
        });
        tr.classList.add('current');
        if (typeof tbody._gridOnRowClick === 'function') {
            tbody._gridOnRowClick(tr, rowData(tr, dataRows(tbody).indexOf(tr)));
        }
    }

    /**
     * tbody의 데이터 행(buildRow로 만든 tr)만. 안내 문구 행(td.empty)·가상 스크롤의 빈 칸 행은 빠진다.
     * 가상 스크롤(virtual)이면 화면에 붙어 있지 않은 행까지 전체다 — 저장(getRows)·엑셀·복사가 보이는 행만 보면 안 된다.
     */
    function dataRows(tbody) {
        if (tbody._gridAllRows) {
            return tbody._gridAllRows.slice();
        }
        return Array.from(tbody.rows).filter(function (tr) { return !!tr._gridColumns; });
    }

    /** 입력 셀 하나의 현재 값 — 행 데이터에 들어가는 형태로 바꾼다. */
    function fieldValue(col, field) {
        if (col.type === 'checkbox') {
            return field.checked ? 'Y' : 'N';
        }
        if (col.type === 'select') {
            return field.value;
        }
        return field.value.trim();
    }

    /** tr 하나의 행 데이터(파일 상단 "행 데이터" 설명 참고). */
    function rowData(tr, index) {
        const data = Object.assign({}, tr._gridRow || {});
        tr._gridColumns.forEach(function (col) {
            if (col.id && col.type && col.type !== 'row-select' && tr._fields && tr._fields[col.id]) {
                data[col.id] = fieldValue(col, tr._fields[col.id]);
            }
        });
        data._rowIndex = index;
        data._isNew = !tr._gridRow;
        data._selected = tr.classList.contains('selected');
        return data;
    }

    /**
     * "신규" 버튼 공통 동작 — 화면마다 반복되던 "안내 행 지우기 → 빈 행을 맨 위에 넣기 → 첫 입력칸 포커스".
     * 포커스는 options.focus(col.id)가 있으면 그 칸, 없으면 체크박스가 아닌 첫 입력칸이다.
     */
    function addRow(tbody, options) {
        options = options || {};
        const columns = tbody._gridColumns;
        if (!columns) {
            throw new Error('Grid.addRow: Grid.renderHeader 또는 Grid.render를 먼저 호출해야 합니다.');
        }

        Array.from(tbody.rows).forEach(function (tr) {
            if (!tr._gridColumns) {
                tr.remove(); // "조회 중입니다..." / "등록된 ... 없습니다." 같은 안내 행
            }
        });

        const tr = buildRow(columns, null, { buildRow: tbody._gridBuildRow });
        tr._gridTbody = tbody;
        if (tbody._gridAllRows) {
            // 가상 스크롤: 전체 행 맨 앞에 넣고 맨 위로 스크롤해 다시 붙인다.
            tbody._gridAllRows.unshift(tr);
            tbody._gridVirtual.container.scrollTop = 0;
            windowRows(tbody, true);
        } else {
            tbody.insertBefore(tr, tbody.firstChild);
        }
        syncSelectAll(tbody);

        const target = options.focus
            ? (tr._fields || {})[options.focus]
            : (tr._orderedFields || []).find(function (field) { return field.type !== 'checkbox'; });
        if (target) {
            target.focus();
        }
        return rowData(tr, 0);
    }

    function getRows(tbody) {
        return dataRows(tbody).map(rowData);
    }

    function getRow(tbody, rowIndex) {
        const tr = dataRows(tbody)[rowIndex];
        return tr ? rowData(tr, rowIndex) : null;
    }

    /** getRows/getRow로 받은 행 데이터에 해당하는 tr을 지운다. 인덱스가 밀리지 않게 먼저 다 찾은 뒤 지운다. */
    function removeRows(tbody, rows) {
        const trs = dataRows(tbody);
        const targets = (rows || [])
            .map(function (row) { return trs[row._rowIndex]; })
            .filter(Boolean);
        if (tbody._gridAllRows) {
            tbody._gridAllRows = tbody._gridAllRows.filter(function (tr) { return targets.indexOf(tr) < 0; });
            windowRows(tbody, true);
        } else {
            targets.forEach(function (tr) { tr.remove(); });
        }
        syncSelectAll(tbody);
    }

    /**
     * 위/아래 행(delta = -1/+1). 형제 노드가 아니라 전체 행 순서로 찾는다 — 가상 스크롤이면 이웃 행이 화면에 붙어 있지 않을 수 있어,
     * 찾은 행을 보이는 자리로 스크롤해 붙인 뒤 돌려준다.
     */
    function neighborRow(tr, delta) {
        const tbody = tr._gridTbody || tr.parentElement;
        if (!tbody) {
            return null;
        }
        const rows = dataRows(tbody);
        const index = rows.indexOf(tr);
        const target = index < 0 ? null : (rows[index + delta] || null);
        if (target && tbody._gridAllRows) {
            revealRow(tbody, index + delta);
        }
        return target;
    }

    /** 다른 행의 입력 필드로 포커스를 옮기고, 클릭했을 때와 똑같이 그 행을 'current'로 강조한다. */
    function focusRowField(row, field) {
        field.focus();
        if (row.parentElement) {
            markRowCurrent(row.parentElement, row);
        }
    }

    /**
     * 위/아래 방향키로 윗/아랫 행의 같은 순번 입력 필드로 포커스를 옮긴다(입력 필드 없는 행에서는 멈춘다).
     * select는 옵션 선택 키라 가로채지 않고, number는 행 이동을 우선한다. 한글 조합 중에는 마지막 글자가
     * 다음 셀로 새지 않도록 무시한다.
     */
    function moveVertical(e, field, tr) {
        if (field.tagName === 'SELECT' || e.isComposing) {
            return;
        }
        e.preventDefault();

        const index = (tr._orderedFields || []).indexOf(field);
        const target = neighborRow(tr, e.key === 'ArrowUp' ? -1 : 1);
        if (index === -1 || !target || !target._orderedFields || target._orderedFields.length === 0) {
            return;
        }
        focusRowField(target, target._orderedFields[Math.min(index, target._orderedFields.length - 1)]);
    }

    /**
     * 엔터로 같은 행의 다음 입력 필드, 마지막이면 다음 행의 첫 입력 필드로 옮긴다(없으면 이벤트만 소비).
     * 다음 행으로 넘어가면 그 행을 'current'로 강조한다. 위/아래 방향키는 moveVertical이 처리한다.
     */
    function bindKeyNavigation(field, tr) {
        field.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                moveVertical(e, field, tr);
                return;
            }
            if (e.key !== 'Enter') {
                return;
            }
            e.preventDefault();

            const fields = tr._orderedFields || [];
            const index = fields.indexOf(field);
            if (index === -1) {
                return;
            }

            if (index < fields.length - 1) {
                fields[index + 1].focus();
                return;
            }

            const nextRow = neighborRow(tr, 1);
            if (nextRow && nextRow._orderedFields && nextRow._orderedFields.length > 0) {
                focusRowField(nextRow, nextRow._orderedFields[0]);
            }
        });
    }

    /** rows 하나를 tr 하나로 만든다. 화면 전체를 다시 그리지 않고 한 행만 추가/교체할 때(예: "신규" 버튼)도 재사용. */
    function buildRow(columns, row, options) {
        options = options || {};
        const tr = document.createElement('tr');
        // 행 데이터(getRows/getRow)를 만들 때 쓴다 — 원본 row와, 어떤 셀이 어떤 컬럼인지.
        tr._gridRow = row || null;
        tr._gridColumns = columns;
        if (options.buildRow) {
            options.buildRow(tr, row);
        }

        columns.forEach(function (col) {
            const td = document.createElement('td');
            if (col.className) {
                td.className = col.className;
            }
            applyColumnStyle(td, col);
            if (col.cursor) {
                td.style.cursor = col.cursor;
            }

            const value = (col.id && row) ? row[col.id] : undefined;

            if (typeof col.render === 'function') {
                const rendered = col.render(value, row, td, tr);
                if (rendered instanceof Node) {
                    td.appendChild(rendered);
                } else if (rendered !== undefined) {
                    td.textContent = rendered;
                }
            } else if (col.type) {
                const field = createFieldElement(col, value, row, tr);
                // 입력칸이 셀을 채우는 셀은 td padding을 없앤다(grid.css .grid-editor-cell) — 체크박스는 제외.
                if (col.type !== 'checkbox' && col.type !== 'row-select') {
                    td.classList.add('grid-editor-cell');
                } else {
                    bindCheckCell(td, field, col.type === 'row-select' && col.stopPropagation);
                }
                if (col.disabled) {
                    field.disabled = typeof col.disabled === 'function' ? !!col.disabled(value, row) : !!col.disabled;
                }
                if (col.readOnly) {
                    field.readOnly = typeof col.readOnly === 'function' ? !!col.readOnly(value, row) : !!col.readOnly;
                }
                if (col.type === 'row-select') {
                    tr._selectField = field; // 헤더 전체 선택이 쓴다
                    field.addEventListener('change', function () {
                        tr.classList.toggle('selected', field.checked);
                        syncSelectAll(tr._gridTbody || tr.parentElement);
                    });
                    if (col.stopPropagation) {
                        field.addEventListener('click', function (e) { e.stopPropagation(); });
                    }
                } else if (col.id) {
                    tr._fields = tr._fields || {};
                    tr._fields[col.id] = field;
                }
                if (col.type === 'select' && typeof col.display === 'function') {
                    // 보기 모드가 있는 select는 숨겨진 채라 포커스를 받을 수 없어 엔터/방향키 이동 순서에서 뺀다.
                    bindKeyNavigation(field, tr);
                    td.appendChild(field);
                    attachDisplayMode(td, field, col, row);
                } else {
                    // type이 있는(입력 가능한) 셀은 전부 왼쪽→오른쪽 순서로 tr._orderedFields에 쌓아서
                    // 엔터 키 이동(다음 셀, 마지막 셀이면 다음 행 첫 셀)과 위/아래 방향키 이동에 쓴다.
                    tr._orderedFields = tr._orderedFields || [];
                    tr._orderedFields.push(field);
                    bindKeyNavigation(field, tr);
                    td.appendChild(field);
                }
            } else {
                td.textContent = (value === null || value === undefined) ? '' : value;
            }

            if (col.title) {
                td.title = typeof col.title === 'function'
                    ? (col.title(value, row) || '')
                    : ((value === null || value === undefined) ? '' : String(value));
            }

            if (typeof col.onDblClick === 'function') {
                td.addEventListener('dblclick', function () {
                    col.onDblClick(value, row);
                });
            }

            tr.appendChild(td);
        });

        return tr;
    }

    // ── 셀 선택 · 우클릭 메뉴(셀 복사 / 행 복사 / 엑셀 다운로드) ─────────────────────

    /** 클릭(또는 엔터·방향키로 포커스가 옮겨 간) 셀을 그 tbody 안에서 유일한 'cell-current'로 만든다(테두리 표시). */
    function markCellCurrent(tbody, td) {
        // tbody에서 찾지 않고 기억해 둔다 — 가상 스크롤로 떼어 둔 행의 셀이면 querySelector로는 안 보여 테두리가 남는다.
        const previous = tbody._gridCurrentCell || tbody.querySelector('td.cell-current');
        if (previous && previous !== td) {
            previous.classList.remove('cell-current');
        }
        td.classList.add('cell-current');
        tbody._gridCurrentCell = td;
    }

    /** 복사·엑셀에 넣는 컬럼 — 값이 있는(col.id) 컬럼만. 행 선택 체크박스와 버튼 열(상세보기·스캔)은 뺀다. */
    function isExportColumn(col) {
        return !!col.id && col.type !== 'row-select';
    }

    /**
     * 셀 하나의 "화면에 보이는 값". 입력 셀은 원본이 아니라 지금 입력된 값이고, select는 코드값 대신
     * 옵션 이름(예: OPEN이 아니라 미해결)이다 — 복사해서 붙여넣거나 엑셀로 받는 사람이 읽을 값이기 때문이다.
     */
    function cellText(tr, colIndex) {
        const col = tr._gridColumns[colIndex];
        const field = col.id && tr._fields ? tr._fields[col.id] : null;
        if (field) {
            if (col.type === 'checkbox') {
                return field.checked ? 'Y' : 'N';
            }
            if (col.type === 'select') {
                const option = field.options[field.selectedIndex];
                return option ? option.textContent : field.value;
            }
            return field.value.trim();
        }
        const td = tr.cells[colIndex];
        return td ? td.textContent.trim() : '';
    }

    /** 행 하나를 탭으로 구분한 한 줄로 — 엑셀에 붙여넣으면 칸별로 나뉜다. 값 안의 탭·줄바꿈은 칸이 밀리지 않게 공백으로. */
    function rowTsv(tr) {
        return tr._gridColumns
            .map(function (col, i) { return isExportColumn(col) ? cellText(tr, i).replace(/[\t\r\n]+/g, ' ') : null; })
            .filter(function (v) { return v !== null; })
            .join('\t');
    }

    /**
     * 클립보드에 쓴다. navigator.clipboard는 https나 localhost에서만 열려서, 사내 IP(http)로 접속하면 없다 —
     * 그때는 숨긴 textarea를 선택해 execCommand('copy')로 복사한다.
     */
    function copyText(text) {
        if (global.navigator.clipboard && global.isSecureContext) {
            return global.navigator.clipboard.writeText(text);
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        const ok = document.execCommand('copy');
        textarea.remove();
        return ok ? Promise.resolve() : Promise.reject(new Error('복사에 실패했습니다.'));
    }

    /** 파일명: 화면 제목(<title>의 " · " 앞부분) + 오늘 날짜. 예: 취약점 관리_20260929.xlsx */
    function exportFileName() {
        const title = (document.title.split(' · ')[0] || 'grid').trim();
        const d = new Date();
        const ymd = d.getFullYear() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
        return title + '_' + ymd + '.xlsx';
    }

    /** 그리드에 지금 그려진 행 전체(조회조건으로 걸러진 결과 그대로, 입력 중인 값 포함)를 엑셀로 내려받는다. */
    function downloadExcel(tbody) {
        const columns = tbody._gridColumns || [];
        const indexes = [];
        columns.forEach(function (col, i) { if (isExportColumn(col)) indexes.push(i); });
        global.XlsxWriter.download(exportFileName(), {
            sheetName: document.title.split(' · ')[0],
            headers: indexes.map(function (i) { return columns[i].label || columns[i].id; }),
            widths: indexes.map(function (i) { return columns[i].width; }),
            rows: dataRows(tbody).map(function (tr) {
                return indexes.map(function (i) { return cellText(tr, i); });
            })
        });
    }

    let contextMenu = null;

    function hideContextMenu() {
        if (contextMenu) {
            contextMenu.style.display = 'none';
        }
    }

    /** 페이지에 하나만 두고 그리드마다 같이 쓴다. 항목 동작은 열 때마다 그 셀·행 기준으로 다시 건다. */
    function ensureContextMenu() {
        if (contextMenu) {
            return contextMenu;
        }
        contextMenu = document.createElement('ul');
        contextMenu.className = 'grid-context-menu';
        contextMenu.addEventListener('contextmenu', function (e) { e.preventDefault(); });
        document.body.appendChild(contextMenu);

        // 메뉴 밖을 누르거나, Esc·스크롤·창 크기 변경이 있으면 닫는다(스크롤하면 메뉴만 엉뚱한 자리에 남는다).
        document.addEventListener('mousedown', function (e) {
            if (!contextMenu.contains(e.target)) hideContextMenu();
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') hideContextMenu();
        });
        document.addEventListener('scroll', hideContextMenu, true);
        global.addEventListener('resize', hideContextMenu);
        global.addEventListener('blur', hideContextMenu);
        return contextMenu;
    }

    function showContextMenu(x, y, items) {
        const menu = ensureContextMenu();
        menu.innerHTML = '';
        items.forEach(function (item) {
            const li = document.createElement('li');
            li.textContent = item.label;
            li.addEventListener('click', function () {
                hideContextMenu();
                Promise.resolve()
                    .then(item.action)
                    .catch(function (err) { alert(err.message || '실행에 실패했습니다.'); });
            });
            menu.appendChild(li);
        });
        menu.style.display = 'block';
        // 화면 오른쪽·아래 끝에서 열면 메뉴가 잘리므로 안쪽으로 밀어 넣는다.
        const rect = menu.getBoundingClientRect();
        menu.style.left = Math.max(0, Math.min(x, global.innerWidth - rect.width - 4)) + 'px';
        menu.style.top = Math.max(0, Math.min(y, global.innerHeight - rect.height - 4)) + 'px';
    }

    /** 이벤트가 난 데이터 셀(td). 안내 문구 행이나 다른 tbody면 null. */
    function dataCell(tbody, target) {
        const td = target.closest('td');
        const tr = td && td.parentElement;
        return (tr && tr.parentElement === tbody && tr._gridColumns) ? td : null;
    }

    /**
     * 데이터 셀 우클릭: 그 셀·행을 선택 표시하고 공통 메뉴를 띄운다. 셀마다 메뉴가 달라지지 않도록
     * 입력 셀(에디터) 위에서도 브라우저 기본 메뉴 대신 공통 메뉴를 쓴다.
     */
    function onContextMenu(tbody, e) {
        const td = dataCell(tbody, e.target);
        if (!td) {
            return;
        }
        const tr = td.parentElement;
        e.preventDefault();
        markCellCurrent(tbody, td);
        markRowCurrent(tbody, tr);

        const colIndex = Array.prototype.indexOf.call(tr.cells, td);
        showContextMenu(e.clientX, e.clientY, [
            { label: '셀 복사', action: function () { return copyText(cellText(tr, colIndex)); } },
            { label: '행 복사', action: function () { return copyText(rowTsv(tr)); } },
            { label: '엑셀 다운로드', action: function () { downloadExcel(tbody); } }
        ]);
    }

    /**
     * tbody에 한 번만 붙는 이벤트 위임. 데이터 행 클릭 시 'current'·'cell-current'를 옮기고 onRowClick을 부르며,
     * 우클릭은 공통 메뉴를 띄운다. 리스너가 tbody에 달려 다시 그려도 유지되므로 최신 콜백만 갱신한다.
     */
    function bindRowClickHighlight(tbody) {
        tbody.addEventListener('click', function (e) {
            const tr = e.target.closest('tr');
            // 데이터 행만 — 안내 문구 행·가상 스크롤의 빈 칸 행은 _gridColumns가 없다.
            if (!tr || tr.parentElement !== tbody || !tr._gridColumns) {
                return;
            }
            const td = e.target.closest('td');
            if (td) {
                markCellCurrent(tbody, td);
            }
            markRowCurrent(tbody, tr);
        });
        // 엔터·방향키로 입력칸 포커스가 다른 셀로 옮겨 가도 테두리가 따라가게 한다.
        tbody.addEventListener('focusin', function (e) {
            const td = e.target.closest('td');
            if (td && td.parentElement && td.parentElement._gridColumns) {
                markCellCurrent(tbody, td);
            }
        });
        // 우클릭은 브라우저가 mousedown에서 입력칸에 포커스(커서)를 먼저 넣어 편집 상태로 바꿔 버린다.
        // 메뉴만 띄우려는 동작이라 입력 셀에서는 그 기본 동작을 막는다(값·포커스는 그대로 둔다).
        tbody.addEventListener('mousedown', function (e) {
            if (e.button === 2 && e.target.matches('input, select, textarea') && dataCell(tbody, e.target)) {
                e.preventDefault();
            }
        });
        tbody.addEventListener('contextmenu', function (e) { onContextMenu(tbody, e); });
        tbody._gridClickBound = true;
    }

    // ── 가상 스크롤(options.virtual) ─────────────────────────────────────
    // 행이 수백 개면 재배치가 느려지므로 보이는 범위(± 여유분)만 붙이고 위아래는 빈 칸 행으로 채운다. tr은 모두 만들어
    // tbody._gridAllRows에 두고 붙였다 떼므로 입력값이 유지되고 getRows·엑셀은 전체를 본다. 행 높이가 일정한 그리드에만 켠다.

    /** 이보다 적으면 다 붙인다 — 계산·빈 칸 행이 더 비싸다. */
    const VIRTUAL_MIN_ROWS = 100;
    /** 보이는 범위 위아래로 미리 붙여 둘 행 수(빠르게 스크롤할 때 빈 화면이 보이지 않게). */
    const VIRTUAL_BUFFER = 20;
    const DEFAULT_ROW_HEIGHT = 32;
    const virtualBodies = new Set();

    function stopVirtual(tbody) {
        tbody._gridAllRows = null;
        tbody._gridVirtual = null;
        virtualBodies.delete(tbody);
    }

    function spacerRow(columnCount, height) {
        const tr = document.createElement('tr');
        tr.className = 'grid-spacer';
        const td = document.createElement('td');
        td.colSpan = columnCount;
        // grid.css의 행 높이·테두리를 덮어써 정확히 이 높이만 차지하게 한다.
        td.style.cssText = 'height:' + height + 'px;padding:0;border:none;';
        tr.appendChild(td);
        return tr;
    }

    /** 지금 스크롤 위치에서 보일 범위의 행만 붙인다. force가 아니면 범위가 그대로일 때 아무것도 하지 않는다. */
    function windowRows(tbody, force) {
        const state = tbody._gridVirtual;
        const rows = tbody._gridAllRows;
        if (!state || !rows) {
            return;
        }
        const viewport = state.container.clientHeight;
        // 숨겨진 탭(iframe)에서는 높이가 0이라 계산할 수 없다 — 다시 보일 때(resize) 계산한다.
        if (viewport === 0 && !force) {
            return;
        }
        const rowHeight = state.rowHeight;
        // tbody 맨 위(빈 칸 행 포함)가 스크롤 영역 위쪽보다 얼마나 올라가 있는가 = 지나간 행 높이.
        const scrolled = Math.max(0, state.container.getBoundingClientRect().top - tbody.getBoundingClientRect().top);
        const visible = Math.ceil((viewport || 600) / rowHeight);
        const start = Math.max(0, Math.min(rows.length, Math.floor(scrolled / rowHeight)) - VIRTUAL_BUFFER);
        const end = Math.min(rows.length, start + visible + VIRTUAL_BUFFER * 2);
        if (!force && start === state.start && end === state.end) {
            return;
        }
        state.start = start;
        state.end = end;

        const columnCount = (tbody._gridColumns || []).length || 1;
        const fragment = document.createDocumentFragment();
        if (start > 0) fragment.appendChild(spacerRow(columnCount, start * rowHeight));
        for (let i = start; i < end; i++) fragment.appendChild(rows[i]);
        if (end < rows.length) fragment.appendChild(spacerRow(columnCount, (rows.length - end) * rowHeight));
        tbody.replaceChildren(fragment);

        // 실제 행 높이를 한 번 재서 맞춘다(화면 CSS가 다르면). 다르면 그 높이로 다시 계산한다.
        if (!state.measured && viewport > 0 && end > start) {
            state.measured = true;
            const measured = rows[start].offsetHeight;
            if (measured > 0 && measured !== rowHeight) {
                state.rowHeight = measured;
                windowRows(tbody, true);
            }
        }
    }

    /** index번째 행이 보이도록 스크롤하고 붙인다(엔터·방향키로 화면 밖 행에 갈 때). */
    function revealRow(tbody, index) {
        const state = tbody._gridVirtual;
        if (!state) {
            return;
        }
        const rows = tbody._gridAllRows;
        if (rows[index] && rows[index].parentElement === tbody) {
            return; // 이미 붙어 있다 — 브라우저 포커스가 알아서 보이게 스크롤한다
        }
        const tbodyTopInContent = tbody.getBoundingClientRect().top - state.container.getBoundingClientRect().top
            + state.container.scrollTop;
        state.container.scrollTop = Math.max(0, tbodyTopInContent + index * state.rowHeight - state.container.clientHeight / 2);
        windowRows(tbody, true);
    }

    function startVirtual(tbody, trs) {
        const table = tbody.closest('table');
        const container = table && table.parentElement;
        tbody._gridAllRows = trs;
        tbody._gridVirtual = { container: container, rowHeight: DEFAULT_ROW_HEIGHT, start: -1, end: -1, measured: false };
        virtualBodies.add(tbody);
        if (container && !container._gridVirtualScrollBound) {
            let scheduled = false;
            container.addEventListener('scroll', function () {
                if (scheduled) return;
                scheduled = true;
                global.requestAnimationFrame(function () {
                    scheduled = false;
                    container.querySelectorAll('tbody').forEach(function (body) {
                        if (body._gridVirtual) windowRows(body, false);
                    });
                });
            }, { passive: true });
            container._gridVirtualScrollBound = true;
        }
        windowRows(tbody, true);
    }

    // 창 크기가 바뀌거나 숨겨졌던 탭(iframe)이 다시 보이면(iframe 안에서 resize가 난다) 보이는 범위를 다시 잡는다.
    global.addEventListener('resize', function () {
        virtualBodies.forEach(function (tbody) {
            if (tbody.isConnected) windowRows(tbody, false);
        });
    });

    function render(tbody, columns, rows, options) {
        options = options || {};
        tbody._gridOnRowClick = options.onRowClick;
        // Grid.addRow가 같은 컬럼·같은 buildRow 콜백으로 신규 행을 만들 수 있게 기억해 둔다.
        tbody._gridColumns = columns;
        tbody._gridBuildRow = options.buildRow;
        if (!tbody._gridClickBound) {
            bindRowClickHighlight(tbody);
        }

        function paint() {
            stopVirtual(tbody);
            tbody._gridCurrentCell = null;
            tbody.innerHTML = '';
            scheduleFitScrollHeights();

            if (!rows || rows.length === 0) {
                clearAndAppendMessage(tbody, columns.length, options.emptyMessage || '조회된 데이터가 없습니다.');
                syncSelectAll(tbody);
                return;
            }

            const trs = rows.map(function (row) {
                const tr = buildRow(columns, row, options);
                tr._gridTbody = tbody; // 떼어 둔 행에서도 자기 tbody를 찾게(neighborRow)
                return tr;
            });
            if (options.virtual && trs.length >= VIRTUAL_MIN_ROWS) {
                startVirtual(tbody, trs);
            } else {
                const fragment = document.createDocumentFragment();
                trs.forEach(function (tr) { fragment.appendChild(tr); });
                tbody.appendChild(fragment);
            }
            syncSelectAll(tbody); // 다시 조회하면 선택이 풀리므로 헤더도 푼다
        }

        // optionsQuery select 컬럼은 그리기 전에 공통코드 옵션을 받아 col.options에 캐시한다(addRow도 그대로 쓴다).
        // 이런 컬럼이 없는 그리드는 동기로 그린다 — render() 직후 tbody를 바로 읽는 화면이 있어 비동기를 끼우면 안 된다.
        const pendingOptionColumns = columns.filter(function (col) {
            return col.type === 'select' && col.optionsQuery && !col._optionsResolved;
        });

        if (pendingOptionColumns.length === 0) {
            paint();
            return;
        }

        Promise.all(pendingOptionColumns.map(function (col) {
            return global.ComCd.fetchCodes(col.optionsQuery).then(function (codes) {
                col.options = codes.map(function (code) {
                    return { value: code.codeValue, label: code.codeName };
                });
                col._optionsResolved = true;
            });
        })).then(paint);
    }

    /** 조회 실패 등 에러 문구를 같은 모양(colspan 하나짜리 행)으로 보여줄 때 사용. */
    function renderMessage(tbody, colspan, message) {
        clearAndAppendMessage(tbody, colspan, message);
    }

    global.Grid = {
        render: render,
        renderMessage: renderMessage,
        renderHeader: renderHeader,
        getRows: getRows,
        getRow: getRow,
        removeRows: removeRows,
        addRow: addRow,
        // 그리드 밖(조치안 화면의 pom.xml 모달 등)에서도 같은 폴백으로 복사하도록 공개한다.
        copyText: copyText
    };
})(window);
