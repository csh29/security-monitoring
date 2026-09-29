/**
 * 화면마다 반복되던 "tr/td를 하나씩 만들어 append" 코드를 대체하는 공통 그리드 렌더러.
 * 헤더(th)도 마크업에 직접 적지 않고 이 columns 정의로부터 Grid.renderHeader가 만든다.
 * .grid 공통 CSS는 이 파일이 아니라 /css/grid.css에 있다 — <head>에
 * <link rel="stylesheet" href="/css/grid.css">로 넣어야 한다(JS로 런타임에 넣으면 스크립트가
 * 실행되기 전까지 스타일이 없어 화면이 깜빡인다).
 *
 * 사용법:
 *   Grid.renderHeader(thead, columns, { initialMessage });
 *   Grid.getRows(tbody)            // 모든 행 데이터(아래 "행 데이터")
 *   Grid.getRow(tbody, rowIndex)   // rowIndex(0부터, 안내 행 제외) 번째 행 데이터. 없으면 null
 *   Grid.removeRows(tbody, rows)   // getRows로 받은 행 데이터에 해당하는 tr을 지운다(저장 전 신규 행 삭제 등)
 *   Grid.addRow(tbody, { focus })  // "신규" 버튼: 맨 위에 빈 행을 넣고 첫 입력칸(또는 focus로 준 col.id)에 커서를 둔다.
 *                                  // 컬럼은 renderHeader/render에 준 것을 그대로 쓴다. 새 행의 행 데이터를 돌려준다.
 *
 * 행 데이터: 그 행을 그릴 때 받은 원본 row 객체에, 입력 셀(type이 있는 컬럼)의 현재 값을 col.id로
 * 덮어쓴 새 객체. 화면이 tr._fields.xxx.value / tr.dataset.id를 직접 읽지 않고 이걸로 읽는다.
 *   - text/number/password : 앞뒤 공백을 뺀 문자열(number도 문자열 — 숫자가 필요하면 화면이 변환)
 *   - checkbox             : 'Y' / 'N'
 *   - select               : 선택된 value
 *   - _rowIndex            : getRow에 넘기는 그 행의 순번
 *   - _isNew               : 원본 row 없이 만든 행("신규" 버튼으로 추가해 아직 저장 전)이면 true
 *   - _selected            : row-select 체크박스로 선택된 행이면 true("삭제" 대상)
 *   Grid.render(tbody, columns, rows, options);
 *
 * columns: [{ id, label, width, align, cursor, className, headerClassName, type, render(value, row, td, tr), title(value, row) }]
 *   - id        : row 객체에서 꺼낼 속성명. 값은 td.textContent로(또는 type이 있으면 그 입력 엘리먼트
 *                 값으로) 그대로 들어간다.
 *   - label     : 헤더 th에 표시할 텍스트. 생략하면 빈 th(체크박스 열 등).
 *   - width     : 컬럼 폭. 숫자면 px, 문자열이면 그대로(예: '20%') th/td에 inline style로 적용된다.
 *                 화면 <style> 태그에 ".grid th.xxx{width:...}" 식으로 적지 않고 이 값 하나로 통일한다.
 *   - align     : td의 text-align('center'/'right'/'left'). 배지·체크박스·버튼 열 정렬에 사용.
 *                 헤더(th) label은 모든 그리드에서 가운데 정렬이라(grid.css) 여기에 영향받지 않는다.
 *   - cursor    : td의 cursor 스타일(예: 'pointer'). onDblClick으로 팝업을 여는 열 등에 사용.
 *   - className : td에 적용할 클래스. headerClassName이 없으면 th에도 그대로 적용된다.
 *   - headerClassName : th에만 다른 클래스를 적용하고 싶을 때만 지정.
 *   - render    : 지정하면 기본 텍스트 대신 이 결과로 셀을 채운다. Node를 리턴하면 그대로
 *                 append(입력창/배지/버튼 등), 문자열/숫자를 리턴하면 textContent로 넣는다.
 *                 (value, row, td, tr) 네 값을 다 받으므로, 체크박스처럼 tr에 class/dataset을
 *                 걸어야 하는 셀도 이 콜백 안에서 처리하면 된다. render가 없으면 아래 type으로
 *                 화면마다 반복되던 "input 만들고 tr._fields에 담는" 코드를 대신할 수 있다.
 *   - type      : render 없이 입력 엘리먼트를 선언적으로 만든다(각 화면의 createInput류 함수 대체).
 *       - 'text' | 'number' | 'password' (기본 'text') : <input>. value는 row[col.id](신규 행이면 빈 값).
 *       - 'checkbox' : Y/N 필드용 <input type="checkbox">. checked는 기본 row[col.id]==='Y'이고,
 *                      신규 행(row가 null)이면 col.defaultChecked(기본 true). col.checked(value,row,tr)를
 *                      주면 그 값을 대신 쓴다 — 체크박스가 row[col.id]가 아닌 다른 데이터(예: 권한
 *                      부여 여부 Set)에 묶여 있는 경우에 쓴다.
 *       - 'select'   : <select>. col.options(row) 또는 [{value,label}] 배열로 옵션을 채우고, 선택값은
 *                      row[col.id](신규 행이면 col.defaultValue). col.options 대신 col.optionsQuery에
 *                      공통코드 그룹명(예: 'ROLE')을 주면, 화면이 직접 조회하지 않아도 render()가
 *                      ComCd.fetchCodes(optionsQuery) 결과로 옵션을 채워준다(codeValue→value,
 *                      codeName→label). 그리드마다 반복되던 "그룹 조회 → 캐시 변수 → options 함수"
 *                      배선을 없애는 용도라, 이 화면은 /js/com-cd.js를 같이 불러와야 한다.
 *       - 'row-select': 그리드 상단 "삭제" 버튼이 쓰는 행 선택 체크박스 — 값을 저장하지 않고
 *                      change 시 tr에 'selected' 클래스만 토글한다. col.id는 필요 없다.
 *     만들어진 엘리먼트는 col.id가 있으면 tr._fields[col.id]에 저장돼, 기존처럼 저장 로직에서
 *     tr._fields.xxx.value(또는 .checked)로 읽으면 된다. col.disabled(value,row)로 비활성화,
 *     col.readOnly(value,row)로 읽기전용(자연키처럼 값은 보여주되 수정은 막을 때 — disabled는
 *     클릭/포커스 자체가 안 먹어서 행 클릭이 씹히니, 클릭은 되어야 하는 셀엔 readOnly를 쓴다),
 *     col.placeholder(문자열 또는 함수)로 placeholder를 줄 수 있고, row-select에 한해
 *     col.stopPropagation을 true로 주면 클릭이 행(tr)까지 버블링되지 않는다(행 클릭에 별도
 *     동작이 걸려 있는 화면에서 체크박스 클릭과 충돌하지 않게 하기 위함).
 *   - title     : true면 텍스트 값을 그대로 title(툴팁)로 쓰고, 함수면 (value, row)의 리턴값을 쓴다.
 *   - onDblClick: (value, row)를 받는 콜백 — 더블클릭 시 실행(설명 팝업 등에 사용).
 *   - display   : select 전용 보기 모드. (value, label, row)를 받아 노드(뱃지 등)나 문자열을 돌려주면 평소엔
 *                 그걸 보여주고, 셀을 누를 때만 select로 바뀐다(포커스가 빠지면 새 값으로 다시 그림).
 *                 값 읽기(getRows)는 보통 select 셀과 같다. 예: 취약점 관리의 처리여부 뱃지.
 *
 * type이 있는 셀은 전부 엔터 키로 다음 셀(우측, 마지막 셀이면 다음 행 첫 셀)로, 위/아래 방향키로
 * 윗/아랫 행의 같은 열 셀로 자동 이동한다 — 화면이 따로 처리할 필요 없이 buildRow가 붙여준다.
 * 넘어갈 셀이 없으면 그냥 끝난다. select 셀에서는 방향키가 옵션 선택이라 이동하지 않는다.
 *
 * options:
 *   - emptyMessage : rows가 없을 때 보여줄 문구.
 *   - buildRow(tr, row) : 각 tr 생성 직후(셀 채우기 전) 호출 — dataset/class 지정용.
 *   - onRowClick(tr, row) : 행을 클릭하면(체크박스처럼 stopPropagation을 건 셀이 아닌 한) 호출된다.
 *                       row는 그 행의 행 데이터(getRow와 같은 값)다.
 *                       클릭한 행은 render()가 자동으로 'current' 클래스를 붙여 강조 표시하므로,
 *                       공통코드관리 화면처럼 "행을 클릭하면 우측에 상세를 보여준다" 같은 동작만
 *                       이 콜백에 얹으면 된다.
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
     * .grid-scroll의 세로 한도를 "그 영역의 시작 위치부터 화면(또는 탭 iframe) 아래 끝까지"로 맞춘다.
     * 그래야 행이 많을 때 페이지가 아니라 그리드 본문만 스크롤되고 헤더(sticky)가 고정된다.
     * 조회영역(SearchForm)처럼 그리드보다 늦게 그려지는 것이 있어 위치가 바뀌므로, 헤더/행을 그릴
     * 때마다와 창 크기가 바뀔 때마다 다시 계산한다. 화면이 스스로 스크롤 영역을 둔 경우(.grid-wrap)는
     * 감싸지 않으므로 대상이 아니다.
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
     * columns 정의로 thead 한 줄(th 목록)을 만든다. 화면마다 <thead>에 th를 직접 적지 않고 이걸로 통일한다.
     *
     * 같은 table의 tbody에는 첫 조회 결과가 오기 전까지 보여줄 안내 행을 같이 넣는다 — 화면마다
     * <tbody>에 "조회 중입니다..." 행과 colspan을 직접 적던 것을 대신한다(colspan은 컬럼 수로 자동).
     * 문구는 options.initialMessage로 바꾼다(예: '좌측에서 그룹을 선택하세요.').
     * tbody에 이미 행이 있으면(헤더만 다시 그리는 경우) 건드리지 않는다.
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
            tr.appendChild(th);
        });

        thead.appendChild(tr);

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

    function clearAndAppendMessage(tbody, colspan, message) {
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
        Array.from(tbody.querySelectorAll('tr.current')).forEach(function (other) {
            if (other !== tr) {
                other.classList.remove('current');
            }
        });
        tr.classList.add('current');
        if (typeof tbody._gridOnRowClick === 'function') {
            tbody._gridOnRowClick(tr, rowData(tr, dataRows(tbody).indexOf(tr)));
        }
    }

    /** tbody의 데이터 행(buildRow로 만든 tr)만. 안내 문구 행(td.empty)은 빠진다. */
    function dataRows(tbody) {
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
        tbody.insertBefore(tr, tbody.firstChild);

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
        (rows || [])
            .map(function (row) { return trs[row._rowIndex]; })
            .filter(Boolean)
            .forEach(function (tr) { tr.remove(); });
    }

    /** 다른 행의 입력 필드로 포커스를 옮기고, 클릭했을 때와 똑같이 그 행을 'current'로 강조한다. */
    function focusRowField(row, field) {
        field.focus();
        if (row.parentElement) {
            markRowCurrent(row.parentElement, row);
        }
    }

    /**
     * 위/아래 방향키: 윗/아랫 행의 같은 열(같은 순번의 입력 필드)로 포커스를 옮긴다. 그 행의 입력
     * 필드가 더 적으면 마지막 필드로 간다. 입력 필드가 없는 행(빈 메시지 행 등)은 건너뛰지 않고
     * 거기서 멈춘다 — 그리드 끝에서 누르면 아무 일도 없다.
     *
     * select는 방향키가 옵션을 바꾸는 키라 가로채지 않는다. number 입력은 방향키가 값 증감이지만
     * 그리드에서는 행 이동이 우선이라 가로챈다(값은 직접 입력). 한글 조합 중에는 무시한다 —
     * 조합이 끝나기 전에 포커스가 넘어가면 마지막 글자가 다음 셀로 새어 들어간다.
     */
    function moveVertical(e, field, tr) {
        if (field.tagName === 'SELECT' || e.isComposing) {
            return;
        }
        e.preventDefault();

        const index = (tr._orderedFields || []).indexOf(field);
        const target = e.key === 'ArrowUp' ? tr.previousElementSibling : tr.nextElementSibling;
        if (index === -1 || !target || !target._orderedFields || target._orderedFields.length === 0) {
            return;
        }
        focusRowField(target, target._orderedFields[Math.min(index, target._orderedFields.length - 1)]);
    }

    /**
     * type이 있는 셀에서 엔터를 누르면 같은 행의 다음 입력 필드로, 그 행의 마지막 필드였으면
     * 다음 tr의 첫 번째 입력 필드로 포커스를 옮긴다(스프레드시트 Tab처럼). 다음 행이 없거나
     * 다음 행에 입력 필드가 없으면 그냥 끝낸다 — 아무 데도 안 옮기고 이벤트만 소비한다.
     * 다음 행으로 넘어갈 때는 클릭했을 때와 똑같이 그 행을 'current'로 강조한다.
     * 위/아래 방향키는 moveVertical이 처리한다.
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

            const nextRow = tr.nextElementSibling;
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
                }
                if (col.disabled) {
                    field.disabled = typeof col.disabled === 'function' ? !!col.disabled(value, row) : !!col.disabled;
                }
                if (col.readOnly) {
                    field.readOnly = typeof col.readOnly === 'function' ? !!col.readOnly(value, row) : !!col.readOnly;
                }
                if (col.type === 'row-select') {
                    field.addEventListener('change', function () {
                        tr.classList.toggle('selected', field.checked);
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

    /**
     * tbody 하나에 한 번만 붙는 클릭 위임 — 실제 데이터 행(빈 메시지 행 제외)을 클릭하면 다른
     * 행의 'current'는 지우고 클릭한 행에만 붙인 뒤 options.onRowClick(tr)을 호출한다.
     * render()가 매번 tbody.innerHTML을 비우고 다시 그려도, 리스너는 tbody 자체에 달려 있어
     * 다시 붙일 필요가 없다 — 최신 onRowClick 콜백만 tbody에 갱신해둔다.
     */
    function bindRowClickHighlight(tbody) {
        tbody.addEventListener('click', function (e) {
            const tr = e.target.closest('tr');
            if (!tr || tr.parentElement !== tbody || tr.querySelector(':scope > td.empty')) {
                return;
            }
            markRowCurrent(tbody, tr);
        });
        tbody._gridClickBound = true;
    }

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
            tbody.innerHTML = '';
            scheduleFitScrollHeights();

            if (!rows || rows.length === 0) {
                clearAndAppendMessage(tbody, columns.length, options.emptyMessage || '조회된 데이터가 없습니다.');
                return;
            }

            rows.forEach(function (row) {
                tbody.appendChild(buildRow(columns, row, options));
            });
        }

        // col.optionsQuery가 붙은 select 컬럼은 그리는 것보다 먼저 공통코드에서 옵션을 받아와야
        // 한다. 한 번 받아오면 col.options에 캐시해두고(col._optionsResolved) 다음 render()부터는
        // 다시 조회하지 않는다 — "신규" 버튼(Grid.addRow)처럼 행 하나만 따로 만드는 곳도 이
        // col.options를 그대로 쓰므로, 조회 화면이 최초 한 번 render()를 호출한 뒤부터는 화면이
        // 신경 쓸 필요가 없다. 이런 컬럼이 없는(대다수) 그리드는 예전처럼 완전히 동기로 그려진다
        // — render() 호출 직후 tbody를 바로 조회하는 화면(공통코드관리 등)이 있어서, 있지도 않은
        // 비동기 대기를 끼워 넣으면 안 된다.
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
        addRow: addRow
    };
})(window);
