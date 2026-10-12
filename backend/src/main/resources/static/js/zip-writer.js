/**
 * 압축 없이(stored) 묶는 최소 zip 작성기. xlsx 생성과 폴더 업로드(서버의 zip 검사를 그대로 받게 zip으로 묶는다)가 쓴다.
 * ZIP64 미사용이라 65,535개·4GB 미만만 만들며(넘으면 예외), 한글 경로가 깨지지 않게 파일명을 UTF-8 표시와 함께 넣는다.
 *
 * 사용법:
 *   const blob = ZipWriter.storedBlob([{ name: 'src/A.java', data: Uint8Array }, ...], 'application/zip');
 */
(function (global) {
    const MAX_ENTRIES = 65535;
    const MAX_BYTES = 0xFFFFFFFF;
    const UTF8_FLAG = 0x0800;

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

    /** files: [{ name, data(Uint8Array) }] → zip Blob(type). 파일이 너무 많거나 크면 예외(ZIP64 미지원). */
    function storedBlob(files, type) {
        if (files.length > MAX_ENTRIES) {
            throw new Error('파일이 너무 많아 zip으로 묶을 수 없습니다(' + files.length + '개, 최대 ' + MAX_ENTRIES + '개).');
        }
        const encoder = new TextEncoder();
        const stamp = dosDateTime(new Date());
        const parts = [];
        const central = [];
        let offset = 0;

        files.forEach(function (file) {
            const name = encoder.encode(file.name);
            const crc = crc32(file.data);
            const size = file.data.length;
            if (offset + 30 + name.length + size > MAX_BYTES) {
                throw new Error('전체 크기가 4GB를 넘어 zip으로 묶을 수 없습니다.');
            }

            const local = new DataView(new ArrayBuffer(30));
            local.setUint32(0, 0x04034b50, true);  // 로컬 파일 헤더 시그니처
            local.setUint16(4, 20, true);          // 필요 버전
            local.setUint16(6, UTF8_FLAG, true);   // 파일명 UTF-8
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
            entry.setUint16(8, UTF8_FLAG, true);
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

        return new Blob(parts.concat(central, [new Uint8Array(end.buffer)]), { type: type || 'application/zip' });
    }

    global.ZipWriter = { storedBlob: storedBlob };
})(window);
