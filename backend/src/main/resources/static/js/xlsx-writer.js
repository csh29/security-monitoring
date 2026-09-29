/**
 * 표 데이터 하나를 .xlsx 파일로 만들어 내려받게 하는 최소 구현(외부 라이브러리 없음). 그리드 우클릭
 * "엑셀 다운로드"(grid.js)가 쓴다. loading-overlay.html이 모든 화면에 싣는다.
 *
 *   XlsxWriter.download('취약점 관리_20260929.xlsx', {
 *       sheetName: '취약점 관리',
 *       headers: ['CVE ID', 'Version'],
 *       widths: [120, 90],                  // 선택. 화면 px 폭 — 엑셀 열 너비로 대략 환산한다
 *       rows: [['CVE-2022-22965', '5.3.17'], ...]
 *   });
 *
 * CSV가 아니라 xlsx로 만드는 이유: CSV는 엑셀이 열 때 값을 추측 변환한다 — 버전 "1.10"이 숫자 1.1로,
 * "2024-01-01"이 날짜로 바뀐다. 버전 문자열이 핵심인 화면이라 모든 셀을 문자열(inlineStr)로 넣는다.
 *
 * xlsx는 XML 몇 개를 zip으로 묶은 것이라, 압축 없이(stored) 묶는 zip 작성기를 여기 같이 둔다.
 */
(function (global) {
    const MAX_CELL_LENGTH = 32767; // 엑셀 셀 한 칸의 최대 글자 수
    const HEADER_FILL = 'FF1F3864'; // 헤더 배경 RGB(31,56,100). 엑셀 색은 ARGB(앞 FF = 불투명)

    // ── zip(무압축) ──────────────────────────────────────────────
    const CRC_TABLE = (function () {
        const table = new Uint32Array(256);
        for (let n = 0; n < 256; n++) {
            let c = n;
            for (let k = 0; k < 8; k++) {
                c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            table[n] = c >>> 0;
        }
        return table;
    })();

    function crc32(bytes) {
        let crc = 0xFFFFFFFF;
        for (let i = 0; i < bytes.length; i++) {
            crc = CRC_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    function dosDateTime(date) {
        return {
            time: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
            date: ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()
        };
    }

    /** files: [{ name, data(Uint8Array) }] → zip Blob. 파일명은 ASCII만 쓴다(xlsx 내부 경로). */
    function zipStored(files) {
        const encoder = new TextEncoder();
        const stamp = dosDateTime(new Date());
        const parts = [];
        const central = [];
        let offset = 0;

        files.forEach(function (file) {
            const name = encoder.encode(file.name);
            const crc = crc32(file.data);
            const size = file.data.length;

            const local = new DataView(new ArrayBuffer(30));
            local.setUint32(0, 0x04034b50, true);  // 로컬 파일 헤더 시그니처
            local.setUint16(4, 20, true);          // 필요 버전
            local.setUint16(8, 0, true);           // 압축 없음(stored)
            local.setUint16(10, stamp.time, true);
            local.setUint16(12, stamp.date, true);
            local.setUint32(14, crc, true);
            local.setUint32(18, size, true);
            local.setUint32(22, size, true);
            local.setUint16(26, name.length, true);
            parts.push(new Uint8Array(local.buffer), name, file.data);

            const entry = new DataView(new ArrayBuffer(46));
            entry.setUint32(0, 0x02014b50, true);  // 중앙 디렉터리 시그니처
            entry.setUint16(4, 20, true);
            entry.setUint16(6, 20, true);
            entry.setUint16(10, 0, true);
            entry.setUint16(12, stamp.time, true);
            entry.setUint16(14, stamp.date, true);
            entry.setUint32(16, crc, true);
            entry.setUint32(20, size, true);
            entry.setUint32(24, size, true);
            entry.setUint16(28, name.length, true);
            entry.setUint32(42, offset, true);     // 로컬 헤더 위치
            central.push(new Uint8Array(entry.buffer), name);

            offset += 30 + name.length + size;
        });

        const centralSize = central.reduce(function (sum, part) { return sum + part.length; }, 0);
        const end = new DataView(new ArrayBuffer(22));
        end.setUint32(0, 0x06054b50, true);        // 중앙 디렉터리 끝 시그니처
        end.setUint16(8, files.length, true);
        end.setUint16(10, files.length, true);
        end.setUint32(12, centralSize, true);
        end.setUint32(16, offset, true);

        return new Blob(parts.concat(central, [new Uint8Array(end.buffer)]),
            { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    }

    // ── xlsx ─────────────────────────────────────────────────────
    /** XML 특수문자 이스케이프 + XML에 들어갈 수 없는 제어문자 제거(NVD 설명 등에 섞여 오면 파일이 안 열린다). */
    function escapeXml(value) {
        return String(value)
            .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '')
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    /** 0 → A, 25 → Z, 26 → AA */
    function columnName(index) {
        let name = '';
        for (let n = index + 1; n > 0; n = Math.floor((n - 1) / 26)) {
            name = String.fromCharCode(65 + ((n - 1) % 26)) + name;
        }
        return name;
    }

    /** 엑셀 시트 이름 규칙: 31자 이하, []:*?/\ 불가, 빈 이름 불가. */
    function safeSheetName(name) {
        const cleaned = String(name || '').replace(/[\[\]:*?\/\\]/g, ' ').trim().slice(0, 31);
        return cleaned || 'Sheet1';
    }

    function cellXml(value, rowNumber, colIndex, styleIndex) {
        let text = (value === null || value === undefined) ? '' : String(value);
        if (text.length > MAX_CELL_LENGTH) {
            text = text.slice(0, MAX_CELL_LENGTH);
        }
        const style = styleIndex ? ' s="' + styleIndex + '"' : '';
        return '<c r="' + columnName(colIndex) + rowNumber + '" t="inlineStr"' + style + '>'
            + '<is><t xml:space="preserve">' + escapeXml(text) + '</t></is></c>';
    }

    function sheetXml(table) {
        const widths = table.widths || [];
        const cols = table.headers.map(function (_, i) {
            // 화면 px를 엑셀 열 너비(기본 글꼴 글자 수)로 대략 환산. 폭 정보가 없으면 15글자.
            const px = typeof widths[i] === 'number' ? widths[i] : 105;
            const width = Math.max(8, Math.min(80, Math.round(px / 7)));
            return '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + width + '" customWidth="1"/>';
        }).join('');

        const header = '<row r="1">' + table.headers.map(function (h, i) {
            return cellXml(h, 1, i, 1); // 스타일 1 = 굵은 글꼴
        }).join('') + '</row>';
        const body = table.rows.map(function (row, r) {
            return '<row r="' + (r + 2) + '">' + row.map(function (v, i) {
                return cellXml(v, r + 2, i, 0);
            }).join('') + '</row>';
        }).join('');

        return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            // 첫 행(헤더) 고정
            + '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
            + '<cols>' + cols + '</cols>'
            + '<sheetData>' + header + body + '</sheetData>'
            + '</worksheet>';
    }

    function buildXlsx(table) {
        const encoder = new TextEncoder();
        const xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
        const files = {
            '[Content_Types].xml': xml
                + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                + '<Default Extension="xml" ContentType="application/xml"/>'
                + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                + '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                + '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                + '</Types>',
            '_rels/.rels': xml
                + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                + '</Relationships>',
            'xl/workbook.xml': xml
                + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                + 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                + '<sheets><sheet name="' + escapeXml(safeSheetName(table.sheetName)) + '" sheetId="1" r:id="rId1"/></sheets>'
                + '</workbook>',
            'xl/_rels/workbook.xml.rels': xml
                + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                + '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                + '</Relationships>',
            // 스타일 0 = 기본, 1 = 헤더(흰 굵은 글꼴 + 배경 HEADER_FILL + 가운데 정렬 — 화면 그리드 헤더와 같다). fills의 none/gray125 두 개는 엑셀이 요구하는
            // 기본값이라 헤더 배경은 세 번째(fillId=2)에 둔다.
            'xl/styles.xml': xml
                + '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                + '<fonts count="2"><font><sz val="11"/><name val="맑은 고딕"/></font>'
                + '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="맑은 고딕"/></font></fonts>'
                + '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
                + '<fill><patternFill patternType="solid"><fgColor rgb="' + HEADER_FILL + '"/><bgColor indexed="64"/></patternFill></fill></fills>'
                + '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                + '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                + '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                + '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1">'
                + '<alignment horizontal="center" vertical="center"/></xf></cellXfs>'
                + '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
                + '</styleSheet>',
            'xl/worksheets/sheet1.xml': sheetXml(table)
        };

        return zipStored(Object.keys(files).map(function (name) {
            return { name: name, data: encoder.encode(files[name]) };
        }));
    }

    function download(filename, table) {
        const url = URL.createObjectURL(buildXlsx(table));
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    global.XlsxWriter = { download: download, build: buildXlsx };
})(window);
