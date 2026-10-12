/**
 * 조회영역(.search-row 안의 label + 입력)을 필드 정의로 만드는 공통 렌더러. 모양은 common-ui.css에 있다.
 *
 * 사용법:
 *   const search = SearchForm.render(sectionEl, [{ id, label, type, ... }, ...], { onSearch: searchFn });
 *   search.values()     // { id: 값 } — text는 trim, multiselect는 값 배열([] = 전체)
 *   search.reset()      // 모든 필드를 기본값으로
 *   search.field(id)    // 그 필드의 엘리먼트
 *   search.matches(row) // 행이 조회조건에 맞는지(화면에서 거를 때)
 *   search.ready        // select 옵션이 다 채워지면 resolve되는 Promise — 첫 조회는 이걸 기다린다
 *
 * fields:
 *   - id           : values()의 키이자 엘리먼트 id("fld" + 첫 글자 대문자).
 *   - label        : 입력 앞 라벨.
 *   - type         : 'text'(기본) | 'select' | 'multiselect'(체크박스 목록, 안 고르면 전체).
 *   - width        : 입력 폭(숫자면 px, 생략하면 180px).
 *   - placeholder  : text의 placeholder.
 *   - defaultValue : 처음 값이자 reset() 값. select는 생략하면 첫 옵션, multiselect는 값 배열.
 *   - options      : [{value,label}] 배열, 또는 그 배열(Promise 포함)을 돌려주는 함수.
 *   - optionsQuery : options 대신 공통코드 그룹명(com-cd.js 필요).
 *   - withAll      : select 맨 앞에 빈 값 "전체" 옵션을 넣는다(문구는 allLabel).
 *   - onChange     : (value, values) — 값이 바뀌자마자 조회할 필드에 쓴다.
 *   - match        : (value, keyword) → boolean. matches()에서 부분 일치 대신 쓸 비교 함수.
 *
 * options:
 *   - onSearch : text 필드에서 Enter를 누르면 호출된다.
 *
 * matches(row): text는 row[id]의 대소문자 무시 부분 일치, multiselect는 고른 값 포함 여부를 보고 select는 보지 않는다
 *   (빈 조건은 통과). 그래서 필드 id를 행 데이터 키와 같게 준다.
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

    /** select·multiselect 옵션을 채운다. 옵션 출처(공통코드/함수/배열)와 상관없이 Promise로 돌려준다. */
    function loadOptions(select, field, fill) {
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
        return source.then(function (items) {
            if (fill) fill(items);
            else fillOptions(select, field, items);
        });
    }

    /**
     * 여러 값 고르기. select처럼 보이는 상자(button)와 그 아래 펼쳐지는 체크박스 목록. 상자 바깥을 누르거나 Esc면 닫힌다.
     * 반환한 객체는 다른 필드 엘리먼트처럼 elements에 들어가고, values()·reset()·onChange는 이 객체의 메서드로 처리한다.
     */
    function createMultiSelect(field, onChange) {
        const allLabel = field.allLabel || '전체';
        const root = document.createElement('div');
        root.className = 'multi-select';
        const box = document.createElement('button');
        box.type = 'button';
        box.className = 'multi-select-box';
        box.textContent = allLabel;
        const panel = document.createElement('div');
        panel.className = 'multi-select-panel';
        panel.hidden = true;
        root.appendChild(box);
        root.appendChild(panel);
        let items = [];

        function checkboxes() {
            return Array.from(panel.querySelectorAll('input[type="checkbox"]'));
        }

        function selected() {
            return checkboxes().filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
        }

        /** 상자 글자 — 고른 이름들(전부 골랐거나 하나도 안 골랐으면 "전체"). 길면 상자 폭에서 말줄임, 전체 목록은 툴팁. */
        function refreshBox() {
            const values = selected();
            const labels = items.filter(function (i) { return values.indexOf(String(i.value)) >= 0; })
                .map(function (i) { return i.label; });
            box.textContent = values.length === 0 || values.length === items.length ? allLabel : labels.join(', ');
            box.title = box.textContent;
        }

        function setValues(values) {
            const wanted = (values || []).map(String);
            checkboxes().forEach(function (c) { c.checked = wanted.indexOf(c.value) >= 0; });
            refreshBox();
        }

        function close() {
            panel.hidden = true;
            document.removeEventListener('mousedown', onOutside, true);
            document.removeEventListener('keydown', onKey, true);
        }

        function onOutside(e) {
            if (!root.contains(e.target)) close();
        }

        function onKey(e) {
            if (e.key === 'Escape') {
                close();
                box.focus();
            }
        }

        box.addEventListener('click', function () {
            if (!panel.hidden) {
                close();
                return;
            }
            panel.hidden = false;
            // 열려 있는 동안만 문서 전체 이벤트를 듣는다(닫히면 바로 뗀다).
            document.addEventListener('mousedown', onOutside, true);
            document.addEventListener('keydown', onKey, true);
        });

        return {
            root: root,
            box: box,
            fill: function (list) {
                items = list || [];
                panel.innerHTML = '';
                items.forEach(function (item) {
                    const row = document.createElement('label');
                    row.className = 'multi-select-option';
                    const check = document.createElement('input');
                    check.type = 'checkbox';
                    check.value = item.value;
                    check.addEventListener('change', function () {
                        refreshBox();
                        if (onChange) onChange();
                    });
                    row.appendChild(check);
                    row.appendChild(document.createTextNode(item.label));
                    panel.appendChild(row);
                });
                setValues(field.defaultValue);
            },
            values: selected,
            reset: function () { setValues(field.defaultValue); }
        };
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
                if (field.type === 'multiselect') result[field.id] = el.values();
                else result[field.id] = field.type === 'select' ? el.value : el.value.trim();
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
            if (field.type === 'multiselect') {
                const multi = createMultiSelect(field, field.onChange ? function () { field.onChange(multi.values(), values()); } : null);
                loads.push(loadOptions(null, field, multi.fill));
                multi.box.id = elementId(field.id);
                applyWidth(multi.box, field.width);
                elements[field.id] = multi;
                wrap.appendChild(label);
                wrap.appendChild(multi.root);
                container.appendChild(wrap);
                return;
            }
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
            // multiselect는 상자(button) 엘리먼트를 돌려준다(포커스·비활성화용). 값은 values()로 읽는다.
            field: function (id) { return elements[id] && elements[id].box ? elements[id].box : elements[id]; },
            matches: function (row) {
                const cond = values();
                return fields.every(function (field) {
                    if (field.type === 'select') return true;
                    if (field.type === 'multiselect') {
                        return cond[field.id].length === 0 || cond[field.id].indexOf(String(row[field.id])) >= 0;
                    }
                    if (field.match) return !cond[field.id] || field.match(row[field.id], cond[field.id]);
                    return containsIgnoreCase(row[field.id], cond[field.id]);
                });
            },
            reset: function () {
                fields.forEach(function (field) {
                    const el = elements[field.id];
                    if (field.type === 'multiselect') {
                        el.reset();
                    } else if (field.type === 'select') {
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
