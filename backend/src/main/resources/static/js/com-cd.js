/**
 * 공통코드(/api/com-cds)로 화면의 select 옵션을 채운다. 같은 그룹은 페이지당 한 번만 조회하도록 캐시한다.
 *
 * 사용법:
 *   ComCd.fillSelect(selectEl, 'VULN_STATUS', { withAll: true, allLabel: '전체', selected: 'OPEN' });
 *   ComCd.fetchCodes('ROLE').then(function (codes) { ... }); // 행마다 select를 만드는 그리드용
 */
(function (global) {
    const cache = {};

    /** group의 사용중인(useYn=Y) 코드 목록을 정렬순서대로 가져온다. 그룹당 한 번만 fetch하고 이후엔 캐시를 재사용한다. */
    function fetchCodes(group) {
        if (!cache[group]) {
            cache[group] = fetch('/api/com-cds?group=' + encodeURIComponent(group))
                .then(function (res) {
                    if (!res.ok) throw new Error('공통코드(' + group + ') 조회에 실패했습니다.');
                    return res.json();
                })
                .catch(function (err) {
                    delete cache[group];
                    throw err;
                });
        }
        return cache[group];
    }

    function fillOptions(select, codes, options) {
        options = options || {};
        select.innerHTML = '';

        if (options.withAll) {
            const allOption = document.createElement('option');
            allOption.value = '';
            allOption.textContent = options.allLabel || '전체';
            select.appendChild(allOption);
        }

        codes.forEach(function (code) {
            const option = document.createElement('option');
            option.value = code.codeValue;
            option.textContent = code.codeName;
            select.appendChild(option);
        });

        if (options.selected !== undefined && options.selected !== null) {
            select.value = String(options.selected);
        }
    }

    /**
     * 이미 화면에 있는 <select> 하나를 공통코드로 채운다.
     * options.withAll이면 맨 앞에 빈 값("전체" 등) 옵션을 추가하고, options.selected로 기본 선택값을 지정한다.
     * 채우는 데 쓴 codes 배열을 그대로 resolve하므로, 배지 라벨 매핑(코드값 -> 코드명) 등에도 재사용할 수 있다.
     */
    function fillSelect(select, group, options) {
        return fetchCodes(group).then(function (codes) {
            fillOptions(select, codes, options);
            return codes;
        });
    }

    global.ComCd = { fetchCodes: fetchCodes, fillSelect: fillSelect };
})(window);
