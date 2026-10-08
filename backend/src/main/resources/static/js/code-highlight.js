/**
 * 코드 조각 구문 강조(코드 점검 결과 상세보기). 외부 라이브러리 없이 정규식으로 토큰만 나눈다 — 조각이 열 줄 남짓이라
 * 문법을 다 해석할 필요가 없고, 사내망에서 CDN을 못 쓸 수 있어 xlsx-writer.js처럼 직접 둔다.
 *
 * 사용법:
 *   CodeHighlight.lines(text, CodeHighlight.languageOf('a/B.java'))
 *     → [[{type:'keyword', text:'private'}, {type:'', text:' '}, ...], ...]  줄마다 토큰 배열
 *   화면은 토큰마다 <span class="tok-<type>">을 만들고 textContent로 넣는다(innerHTML을 쓰지 않는다 — 코드 안의 HTML이 실행되지 않게).
 *   색은 common-ui.css의 .code-block .tok-* 에 있다.
 *   CodeHighlight.enableUsages(pre) — 이름(변수·메서드·클래스·상수, MyBatis ${}·#{})을 누르면 같은 이름을 모두 칠한다(IntelliJ의 사용처 강조).
 *
 * 조각은 파일 중간에서 잘린 것이라 여러 줄 주석·태그 한가운데서 시작할 수 있다. 그런 경우 그 부분만 일반 글자로 보일 뿐 깨지지는 않는다.
 */
(function (global) {
    const JAVA_KEYWORDS = 'abstract assert boolean break byte case catch char class const continue default do double else enum ' +
        'extends final finally float for goto if implements import instanceof int interface long native new package private ' +
        'protected public return short static strictfp super switch synchronized this throw throws transient try void volatile ' +
        'while var record yield sealed permits true false null';
    const JS_KEYWORDS = 'async await break case catch class const continue debugger default delete do else export extends ' +
        'finally for function if import in instanceof let new of return static super switch this throw try typeof var void ' +
        'while with yield true false null undefined';
    // MyBatis 매퍼·JSP 안의 SQL. 대소문자를 가리지 않는다.
    const SQL_KEYWORDS = 'select from where and or not in is null like between join inner left right outer full cross on as ' +
        'group by order having union all distinct insert into values update set delete case when then else end exists ' +
        'limit offset asc desc with over partition count sum min max avg coalesce nvl';

    function words(list, flags) {
        return new RegExp('\\b(?:' + list.split(' ').join('|') + ')\\b', flags || '');
    }

    /**
     * 규칙은 [종류, 정규식] 순서대로 시도한다(앞의 것이 이긴다). 정규식은 위치 고정(y) 플래그로 현재 위치에서만 맞춘다.
     * 종류가 함수면 맞은 글자를 다시 쪼갠다(태그 안의 이름·속성·값).
     */
    const C_LIKE_COMMON = [
        ['comment', /\/\*[\s\S]*?(?:\*\/|$)/y],
        ['comment', /\/\/[^\n]*/y],
        ['string', /"""[\s\S]*?(?:"""|$)/y],
        ['string', /"(?:\\.|[^"\\\n])*"?/y],
        ['string', /'(?:\\.|[^'\\\n])*'?/y],
        ['number', /\b(?:0x[\da-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?[lLfFdD]?)\b/y]
    ];

    const RULES = {
        java: C_LIKE_COMMON.concat([
            ['annotation', /@[A-Za-z_][\w.]*/y],
            ['keyword', words(JAVA_KEYWORDS, 'y')],
            ['function', /[a-z_$][\w$]*(?=\s*\()/y],
            // 대문자·숫자·밑줄만인 이름은 상수(static final) — IntelliJ처럼 따로 표시한다.
            ['constant', /[A-Z][A-Z0-9_]*[A-Z0-9](?![\w$])/y],
            ['type', /[A-Z][\w$]*/y],
            ['ident', /[A-Za-z_$][\w$]*/y]
        ]),
        js: C_LIKE_COMMON.concat([
            ['string', /`(?:\\.|[^`\\])*`?/y],
            ['keyword', words(JS_KEYWORDS, 'y')],
            ['function', /[A-Za-z_$][\w$]*(?=\s*\()/y],
            ['ident', /[A-Za-z_$][\w$]*/y]
        ]),
        markup: [
            ['comment', /<!--[\s\S]*?(?:-->|$)/y],
            ['comment', /<%--[\s\S]*?(?:--%>|$)/y],
            ['cdata', /<!\[CDATA\[|\]\]>/y],
            ['tag', /<%[=@!]?|%>/y],
            [splitTag, /<\/?[A-Za-z][\w:.-]*(?:\s+[\w:.@-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*\s*\/?>/y],
            // MyBatis: ${}는 값을 그대로 이어 붙여 위험(점검 규칙이 잡는 대상), #{}는 바인딩.
            ['danger', /\$\{[^}\n]*\}/y],
            ['param', /#\{[^}\n]*\}/y],
            ['string', /'(?:''|[^'\n])*'/y],
            ['keyword', words(SQL_KEYWORDS, 'iy')],
            ['number', /\b\d+(?:\.\d+)?\b/y],
            // 이름에 $를 넣지 않는다 — 넣으면 SU_MEM_INFO_${brndzCd}에서 "SU_MEM_INFO_$"까지 먹어 ${}를 못 알아본다(실제로 그랬다).
            ['', /[A-Za-z_]\w*/y]
        ],
        config: [
            ['comment', /(?:^|(?<=\n))[ \t]*[#!][^\n]*/y],
            // 키 = 값 / 키: 값 — 줄 처음의 키만 키로 본다.
            ['key', /(?:^|(?<=\n))[ \t]*-?[ \t]*[\w.\-\[\]]+(?=[ \t]*[=:])/y],
            // 값은 줄 끝까지 한 색(IntelliJ와 같다) — 안의 IP·포트 숫자까지 따로 칠하면 지저분하다. ${} 참조만 따로 보인다.
            ['param', /\$\{[^}\n]*\}/y],
            ['value', /(?<=(?:^|\n)[ \t]*-?[ \t]*[\w.\-\[\]]+[ \t]*[=:][ \t]*)[^\n$]+/y],
            ['value', /(?<=\})[^\n$]+/y]
        ]
    };

    /** 태그 한 덩어리를 <, 태그 이름, 속성 이름, =, 속성 값, > 로 쪼갠다. */
    function splitTag(text) {
        const out = [];
        const m = /^(<\/?)([^\s/>]+)/.exec(text);
        out.push({ type: 'tag', text: m[1] + m[2] });
        let rest = text.slice(m[0].length);
        const attr = /^(\s+)([\w:.@-]+)(?:(\s*=\s*)("[^"]*"|'[^']*'|[^\s>]+))?/;
        let a;
        while ((a = attr.exec(rest))) {
            out.push({ type: '', text: a[1] });
            out.push({ type: 'attr', text: a[2] });
            if (a[3]) {
                out.push({ type: '', text: a[3] });
                out.push({ type: 'string', text: a[4] });
            }
            rest = rest.slice(a[0].length);
        }
        out.push({ type: 'tag', text: rest });
        return out;
    }

    function tokenize(text, language) {
        const rules = RULES[language];
        if (!rules) return [{ type: '', text: text }];
        const tokens = [];
        let plain = '';
        let pos = 0;
        while (pos < text.length) {
            let matched = null;
            for (const [type, re] of rules) {
                re.lastIndex = pos;
                const m = re.exec(text);
                if (m && m[0].length > 0) {
                    matched = { type: type, text: m[0] };
                    break;
                }
            }
            if (!matched) {
                plain += text[pos++];
                continue;
            }
            if (plain) { tokens.push({ type: '', text: plain }); plain = ''; }
            if (typeof matched.type === 'function') tokens.push.apply(tokens, matched.type(matched.text));
            else tokens.push(matched);
            pos += matched.text.length;
        }
        if (plain) tokens.push({ type: '', text: plain });
        return tokens;
    }

    /** 토큰을 줄 단위로 나눈다 — 여러 줄 주석·문자열은 줄마다 같은 종류로 이어진다. */
    function lines(text, language) {
        const result = [[]];
        tokenize(text, language).forEach(function (token) {
            token.text.split('\n').forEach(function (part, i) {
                if (i > 0) result.push([]);
                if (part) result[result.length - 1].push({ type: token.type, text: part });
            });
        });
        return result;
    }

    /** 파일 확장자로 언어를 고른다. 모르는 확장자는 null(강조 없음). */
    function languageOf(path) {
        const ext = (String(path || '').split('.').pop() || '').toLowerCase();
        if (ext === 'java' || ext === 'kt' || ext === 'groovy') return 'java';
        if (ext === 'js' || ext === 'ts' || ext === 'mjs') return 'js';
        if (['xml', 'html', 'htm', 'jsp', 'jspf', 'tag', 'vue'].indexOf(ext) >= 0) return 'markup';
        if (['properties', 'yml', 'yaml'].indexOf(ext) >= 0) return 'config';
        return null;
    }

    /** 누르면 사용처를 칠하는 토큰 종류 — 이름인 것만(키워드·문자열·주석은 아니다). */
    const SYMBOL_TYPES = ['ident', 'type', 'constant', 'function', 'param', 'danger'];
    const USAGE_CLASS = 'tok-usage';

    /** MyBatis ${loginCompCd}·#{loginCompCd}는 같은 값을 가리키므로 안쪽 이름으로 비교한다. */
    function symbolName(span) {
        const text = span.textContent;
        const m = /^[$#]\{\s*([^,}\s]+)/.exec(text);
        return m ? m[1] : text;
    }

    function symbolOf(target) {
        if (!(target instanceof Element) || !target.classList) return null;
        for (const type of SYMBOL_TYPES) {
            if (target.classList.contains('tok-' + type)) return target;
        }
        return null;
    }

    /**
     * 코드 블록(pre)에서 이름을 누르면 같은 이름을 모두 칠한다. 다시 누르거나 이름이 아닌 곳을 누르면 지운다.
     * 블록 안에서만 찾는다(상세보기의 조각과 연계 추적 걸음 코드는 각자). 이벤트는 블록에 한 번만 건다.
     */
    function enableUsages(pre) {
        if (pre.dataset.usages) return;
        pre.dataset.usages = '1';
        pre.addEventListener('click', function (e) {
            const symbol = symbolOf(e.target);
            const wasSelected = symbol && symbol.classList.contains(USAGE_CLASS);
            pre.querySelectorAll('.' + USAGE_CLASS).forEach(function (el) { el.classList.remove(USAGE_CLASS); });
            if (!symbol || wasSelected) return;
            // 드래그로 코드를 고르는 중이면(복사하려고) 칠하지 않는다.
            const selection = window.getSelection ? window.getSelection() : null;
            if (selection && !selection.isCollapsed) return;
            const name = symbolName(symbol);
            pre.querySelectorAll('span').forEach(function (el) {
                if (symbolOf(el) && symbolName(el) === name) el.classList.add(USAGE_CLASS);
            });
        });
    }

    global.CodeHighlight = { lines: lines, tokenize: tokenize, languageOf: languageOf, enableUsages: enableUsages };
})(window);
