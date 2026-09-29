/**
 * 화면마다 마크업으로 직접 쓰던 조회영역(<section class="search-row"> 안의 label + input/select)을
 * grid.js처럼 필드 정의 하나로 만드는 공통 렌더러. 모양(.search-row/.search-field, label과 입력이
 * 한 줄로 가로 정렬)은 common-ui.css에 있다.
 *
 * 사용법:
 *   <section class="search-row" id="searchArea"></section>
 *
 *   const search = SearchForm.render(document.getElementById('searchArea'), [
 *       { id: 'programId', label: '프로그램ID', type: 'text' },
 *       { id: 'severity',  label: '심각도', type: 'select', optionsQuery: 'SEVERITY', withAll: true }
 *   ], { onSearch: searchPrograms });
 *
 *   search.values()   // { programId: '...', severity: '...' } — text는 trim한 값
 *   search.reset()    // 모든 필드를 기본값으로 되돌린다(초기화 버튼)
 *   search.field(id)  // 그 필드의 input/select 엘리먼트
 *   search.matches(row) // 행 하나가 조회조건에 맞는지 — 목록을 화면에서 거를 때 쓴다(아래 설명)
 *   search.ready      // select 옵션이 다 채워지면 resolve되는 Promise — 첫 조회는 이걸 기다린 뒤 한다
 *
 * fields: [{ id, label, type, width, placeholder, defaultValue, options, optionsQuery, withAll, allLabel, onChange }]
 *   - id           : values()의 키이자 엘리먼트 id("fld" + 첫 글자 대문자, 예: fldProgramId).
 *   - label        : 입력 앞에 붙는 라벨.
 *   - type         : 'text'(기본) | 'select'.
 *   - width        : 입력 폭. 숫자면 px, 문자열이면 그대로. 생략하면 180px.
 *   - placeholder  : text의 placeholder.
 *   - defaultValue : 처음 값이자 reset() 때 돌아갈 값. select에서 생략하면 첫 옵션.
 *   - options      : select 옵션. [{value,label}] 배열, 또는 그 배열(이나 그 배열의 Promise)을 돌려주는
 *                    함수 — 앱 목록·사용자 목록처럼 API로 받아오는 옵션은 함수로 준다.
 *   - optionsQuery : options 대신 공통코드 그룹명(예: 'SEVERITY'). ComCd로 채우므로 이 화면은
 *                    /js/com-cd.js를 같이 불러와야 한다(grid.js의 optionsQuery와 같은 규칙).
 *   - withAll      : select 맨 앞에 값이 빈 "전체" 옵션을 넣는다. allLabel로 문구를 바꾼다.
 *   - onChange     : (value, values) — select처럼 값이 바뀌자마자 조회해야 하는 필드에 쓴다.
 *
 * options:
 *   - onSearch : text 필드에서 Enter를 누르면 호출된다(보통 조회 함수).
 *
 * matches(row): API가 전체 목록만 주는 화면(프로그램·사용자·공통코드 관리)이 조회조건을 화면에서 거를 때
 *   쓴다. text 필드마다 row[field.id]가 입력값을 대소문자 구분 없이 부분 일치로 포함하는지 본다(빈 값은
 *   통과). 그래서 필드 id를 행 데이터의 키와 같게 준다. 화면마다 복사되던 contains/matchesCondition을 대신한다.
 */
(function (global) {
    const DEFAULT_WIDTH = 180;

    function elementId(id) {
        return 'fld' + id.charAt(0).toUpperCase() + id.slice(1);
    }

    function applyWidth(el, width) {
        const w = (width === undefined || width === null) ? DEFAULT_WIDTH : width;
        el.style.width = typeof w === 'number' ? w + 'px' : w;
    }

    function fillOptions(select, field, items) {
        select.innerHTML = '';
        if (field.withAll) {
            const all = document.createElement('option');
            all.value = '';
            all.textContent = field.allLabel || '전체';
            select.appendChild(all);
        }
        (items || []).forEach(function (item) {
            const option = document.createElement('option');
            option.value = item.value;
            option.textContent = item.label;
            select.appendChild(option);
        });
        if (field.defaultValue !== undefined && field.defaultValue !== null) {
            select.value = String(field.defaultValue);
        }
    }

    /** select 옵션을 채운다. 옵션 출처(공통코드/함수/배열)와 상관없이 Promise로 돌려준다. */
    function loadOptions(select, field) {
        let source;
        if (field.optionsQuery) {
            source = global.ComCd.fetchCodes(field.optionsQuery).then(function (codes) {
                return codes.map(function (code) { return { value: code.codeValue, label: code.codeName }; });
            });
        } else if (typeof field.options === 'function') {
            source = Promise.resolve(field.options());
        } else {
            source = Promise.resolve(field.options || []);
        }
        return source.then(function (items) { fillOptions(select, field, items); });
    }

    function containsIgnoreCase(value, keyword) {
        return !keyword || String(value == null ? '' : value).toLowerCase().indexOf(keyword.toLowerCase()) >= 0;
    }

    function render(container, fields, options) {
        options = options || {};
        container.innerHTML = '';
        const elements = {};
        const loads = [];

        function values() {
            const result = {};
            fields.forEach(function (field) {
                const el = elements[field.id];
                result[field.id] = field.type === 'select' ? el.value : el.value.trim();
            });
            return result;
        }

        fields.forEach(function (field) {
            const wrap = document.createElement('div');
            wrap.className = 'search-field';

            const label = document.createElement('label');
            label.htmlFor = elementId(field.id);
            label.textContent = field.label;

            let el;
            if (field.type === 'select') {
                el = document.createElement('select');
                loads.push(loadOptions(el, field));
            } else {
                el = document.createElement('input');
                el.type = 'text';
                el.value = field.defaultValue || '';
                if (field.placeholder) el.placeholder = field.placeholder;
                el.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter' && options.onSearch) options.onSearch();
                });
            }
            el.id = elementId(field.id);
            applyWidth(el, field.width);
            if (field.onChange) {
                el.addEventListener('change', function () { field.onChange(el.value, values()); });
            }

            elements[field.id] = el;
            wrap.appendChild(label);
            wrap.appendChild(el);
            container.appendChild(wrap);
        });

        return {
            values: values,
            field: function (id) { return elements[id]; },
            matches: function (row) {
                const cond = values();
                return fields.every(function (field) {
                    return field.type === 'select' || containsIgnoreCase(row[field.id], cond[field.id]);
                });
            },
            reset: function () {
                fields.forEach(function (field) {
                    const el = elements[field.id];
                    if (field.type === 'select') {
                        el.value = (field.defaultValue !== undefined && field.defaultValue !== null)
                            ? String(field.defaultValue)
                            : (el.options.length ? el.options[0].value : '');
                    } else {
                        el.value = field.defaultValue || '';
                    }
                });
            },
            ready: Promise.all(loads)
        };
    }

    global.SearchForm = { render: render };
})(window);
