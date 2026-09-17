/**
 * 화면마다 반복되던 "tr/td를 하나씩 만들어 append" 코드를 대체하는 공통 그리드 렌더러.
 * 헤더(th)도 마크업에 직접 적지 않고 이 columns 정의로부터 Grid.renderHeader가 만든다.
 * .grid 공통 CSS는 이 파일이 아니라 /css/grid.css에 있다 — <head>에
 * <link rel="stylesheet" href="/css/grid.css">로 넣어야 한다(JS로 런타임에 넣으면 스크립트가
 * 실행되기 전까지 스타일이 없어 화면이 깜빡인다).
 *
 * 사용법:
 *   Grid.renderHeader(thead, columns);
 *   Grid.render(tbody, columns, rows, options);
 *
 * columns: [{ id, label, width, align, cursor, className, headerClassName, type, render(value, row, td, tr), title(value, row) }]
 *   - id        : row 객체에서 꺼낼 속성명. 값은 td.textContent로(또는 type이 있으면 그 입력 엘리먼트
 *                 값으로) 그대로 들어간다.
 *   - label     : 헤더 th에 표시할 텍스트. 생략하면 빈 th(체크박스 열 등).
 *   - width     : 컬럼 폭. 숫자면 px, 문자열이면 그대로(예: '20%') th/td에 inline style로 적용된다.
 *                 화면 <style> 태그에 ".grid th.xxx{width:...}" 식으로 적지 않고 이 값 하나로 통일한다.
 *   - align     : th/td의 text-align('center'/'right'/'left'). 배지·체크박스·버튼 열 정렬에 사용.
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
 *                      row[col.id](신규 행이면 col.defaultValue).
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
 *
 * options:
 *   - emptyMessage : rows가 없을 때 보여줄 문구.
 *   - buildRow(tr, row) : 각 tr 생성 직후(셀 채우기 전) 호출 — dataset/class 지정용.
 *   - onRowClick(tr) : 행을 클릭하면(체크박스처럼 stopPropagation을 건 셀이 아닌 한) 호출된다.
 *                       클릭한 행은 render()가 자동으로 'current' 클래스를 붙여 강조 표시하므로,
 *                       공통코드관리 화면처럼 "행을 클릭하면 우측에 상세를 보여준다" 같은 동작만
 *                       이 콜백에 얹으면 된다.
 */
(function (global) {
    /** width/align 같은 컬럼별 스타일을 화면 <style> 태그 대신 이 inline style로 적용한다. */
    function applyColumnStyle(cell, col) {
        if (col.width !== undefined && col.width !== null) {
            cell.style.width = typeof col.width === 'number' ? col.width + 'px' : col.width;
        }
        if (col.align) {
            cell.style.textAlign = col.align;
        }
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

    /** columns 정의로 thead 한 줄(th 목록)을 만든다. 화면마다 <thead>에 th를 직접 적지 않고 이걸로 통일한다. */
    function renderHeader(thead, columns) {
        thead.innerHTML = '';
        const tr = document.createElement('tr');

        columns.forEach(function (col) {
            const th = document.createElement('th');
            const className = col.headerClassName || col.className;
            if (className) {
                th.className = className;
            }
            applyColumnStyle(th, col);
            th.textContent = col.label || '';
            tr.appendChild(th);
        });

        thead.appendChild(tr);
    }

    function clearAndAppendMessage(tbody, colspan, message, className) {
        tbody.innerHTML = '';
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.className = className || 'empty';
        td.colSpan = colspan;
        td.textContent = message;
        tr.appendChild(td);
        tbody.appendChild(tr);
    }

    /** rows 하나를 tr 하나로 만든다. 화면 전체를 다시 그리지 않고 한 행만 추가/교체할 때(예: "추가" 버튼)도 재사용. */
    function buildRow(columns, row, options) {
        options = options || {};
        const tr = document.createElement('tr');
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
                td.appendChild(field);
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
            Array.from(tbody.querySelectorAll('tr.current')).forEach(function (other) {
                if (other !== tr) {
                    other.classList.remove('current');
                }
            });
            tr.classList.add('current');
            if (typeof tbody._gridOnRowClick === 'function') {
                tbody._gridOnRowClick(tr);
            }
        });
        tbody._gridClickBound = true;
    }

    function render(tbody, columns, rows, options) {
        options = options || {};
        tbody._gridOnRowClick = options.onRowClick;
        if (!tbody._gridClickBound) {
            bindRowClickHighlight(tbody);
        }

        tbody.innerHTML = '';

        if (!rows || rows.length === 0) {
            clearAndAppendMessage(tbody, columns.length, options.emptyMessage || '조회된 데이터가 없습니다.');
            return;
        }

        rows.forEach(function (row) {
            tbody.appendChild(buildRow(columns, row, options));
        });
    }

    /** 조회 실패 등 에러 문구를 같은 모양(colspan 하나짜리 행)으로 보여줄 때 사용. */
    function renderMessage(tbody, colspan, message) {
        clearAndAppendMessage(tbody, colspan, message);
    }

    global.Grid = { render: render, buildRow: buildRow, renderMessage: renderMessage, renderHeader: renderHeader };
})(window);
